# Copyright Hitachi, Ltd. 2023 All Rights Reserved.
#
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import base64
import grpc
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import dateutil.parser
from datetime import datetime, timezone, timedelta
from pathlib import Path

from st2auth.sso import base as st2auth_sso
from st2common.exceptions import auth as auth_exc

import st2auth_immst_backend.immop_pb2 as immop_pb2
import st2auth_immst_backend.immop_pb2_grpc as immop_pb2_grpc

__all__ = [
    'ImmStAuthenticationBackend'
]

LOG = logging.getLogger(__name__)

COMMENT_MARKER = '**COMMENTIGNORE**'

class ImmStAuthenticationBackend(st2auth_sso.BaseSingleSignOnBackend):
    def __init__(self, **kwargs):
        LOG.info('kwargs: {}'.format(kwargs))
        self.imms_ca_file = kwargs.get("imms_ca_cert", "")
        self.imms_server_cert = kwargs.get("imms_server_cert", "")
        self.imms_auth_redirect = kwargs.get("imms_redirect_url", "https://www.example.com/st2web/st2login.html")
        self.st2_referer = kwargs.get("st2_referer", "https://st2web.example.com")

    def get_request_redirect_url(self, referer):
        return self.imms_auth_redirect
    
    def verify_response(self, response):
        LOG.info('verify_response: type: {}'.format(type(response)))
        LOG.info('verify_response: {}'.format(dir(response)))

        verify_rsp_base64 = getattr(response, "response", None)
        if verify_rsp_base64 is None:
            raise auth_exc.SSOVerificationError('unexpected response')
        LOG.info('verify_rsp_base64: type: {}'.format(type(verify_rsp_base64)))
        LOG.info('verify_rsp_base64: {}'.format(verify_rsp_base64))
        verify_rsp = base64.standard_b64decode(verify_rsp_base64)
        
        auth_rsp = immop_pb2.PropReq()
        auth_rsp.ParseFromString(verify_rsp)
        #LOG.info('timestamp: {}'.format(auth_rsp.Msg))

        try:
            with open(self.imms_ca_file, "r") as ca_file:
                ca_cert_raw = ca_file.read().encode()
                ca_cert =  x509.load_pem_x509_certificate(ca_cert_raw)

                cert =  x509.load_pem_x509_certificate(auth_rsp.Cred.Cert)
                ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                            ec.ECDSA(hashes.SHA256()))
                
                now_t = datetime.now()
                if now_t < cert.not_valid_before  or now_t > cert.not_valid_after:
                    raise Exception("this certificate has expired")

                tbs_req = immop_pb2.PropReq()
                tbs_req.Msg = auth_rsp.Msg
                tbs_data = "st2authReq".encode() + tbs_req.SerializeToString()
                cert.public_key().verify(auth_rsp.Cred.Signature, tbs_data, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            LOG.info('verify_response error: {}'.format(e))
            raise auth_exc.SSOVerificationError('invalid certificate: {}'.format(e))

        cn_name_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cn_name_attr) < 1:
            raise auth_exc.SSOVerificationError('invalid certificate: not found commonname')

        try:
            now_t = datetime.now(timezone.utc)
            
            whoami_req = immop_pb2.ImmstFuncRequest()
            whoami_req.ParseFromString(auth_rsp.Msg)
            req_t = dateutil.parser.isoparse(whoami_req.Time)
            delta170s = timedelta(seconds=170)
            if now_t > req_t + delta170s or now_t < req_t - delta170s:
                raise Exception('unexpected timestamp: {}'.format(req_t))
            
            with open(self.imms_server_cert, "rb") as imms_cert_file:
                immsrv_cred = grpc.ssl_channel_credentials(imms_cert_file.read())
                self.channel = grpc.secure_channel('immsrv:50051', immsrv_cred)
                grpc_stub = immop_pb2_grpc.ImmOperationStub(self.channel)
                whoami_rsp = grpc_stub.ImmstFunc(whoami_req)
                if whoami_rsp.Time != "":
                    raise Exception("timeout")
                LOG.info('whoami: {}'.format(whoami_rsp.Rsp))
                
        except Exception as e:
            LOG.info('authentication failure: {}'.format(e))
            raise auth_exc.SSOVerificationError('authentiction failure')
                    

        # verified user

        # write a role assignment file
        username = cn_name_attr[0].value
        rbac_role_file = "/opt/stackstorm/rbac/assignments/"+username+".yaml"
        pipe_file = "/opt/stackstorm/rbac/update"
        if not Path(rbac_role_file).exists():
            with open(rbac_role_file, "w") as assignf, open(pipe_file, "w") as pipef:
                assign_str = """---
username: """ + username + """
roles:
  - role_general
"""
                assignf.write(assign_str)
                pipef.write("update\n")

        # success
        return {
            "referer": self.st2_referer,
            "username": username,
        }

    def authenticate(self, username, password):
        #LOG.info('username: {0}, password: {1}'.format(username, password))
        return False

    def __del__(self):
        if hasattr(self, "channel"):
            self.channel.close()
