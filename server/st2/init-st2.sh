if [ ! -f  /etc/st2/keys/datastore_key.json ]; then
    st2-generate-symmetric-crypto-key --key-path /etc/st2/keys/datastore_key.json
    chown -R st2:st2 /etc/st2/keys
    chmod -R 750 /etc/st2/keys
fi
if [ ! -f /opt/stackstorm/rbac/update ]; then
    mkfifo -m 0660 /opt/stackstorm/rbac/update
    chown -R st2:st2 /opt/stackstorm/rbac
fi
while ! st2-apply-rbac-definitions -v; do
    sleep 10
done
while true; do
    ACTIONS=$(st2 action list)
    if [ "$?" -ne 0 ]; then
        echo "not ready";
        sleep 10
    elif [ "$ACTIONS" == "No matching items found" ]; then
        st2 pack register
    else st2-apply-rbac-definitions -v
         while true; do
             if read line < /opt/stackstorm/rbac/update && [ "$line" = "update" ]; then
                 st2-apply-rbac-definitions -v
             fi
         done & sleep infinity
    fi
done
