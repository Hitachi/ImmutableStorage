// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.24.0
// 	protoc        v3.12.4
// source: proto/immplugin.proto

package immplugin

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type DoPluginRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Creator []byte   `protobuf:"bytes,1,opt,name=Creator,proto3" json:"Creator,omitempty"`
	Args    [][]byte `protobuf:"bytes,2,rep,name=Args,proto3" json:"Args,omitempty"`
}

func (x *DoPluginRequest) Reset() {
	*x = DoPluginRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_immplugin_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DoPluginRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DoPluginRequest) ProtoMessage() {}

func (x *DoPluginRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_immplugin_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DoPluginRequest.ProtoReflect.Descriptor instead.
func (*DoPluginRequest) Descriptor() ([]byte, []int) {
	return file_proto_immplugin_proto_rawDescGZIP(), []int{0}
}

func (x *DoPluginRequest) GetCreator() []byte {
	if x != nil {
		return x.Creator
	}
	return nil
}

func (x *DoPluginRequest) GetArgs() [][]byte {
	if x != nil {
		return x.Args
	}
	return nil
}

type DoPluginReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Func  string `protobuf:"bytes,1,opt,name=Func,proto3" json:"Func,omitempty"`
	Key   string `protobuf:"bytes,2,opt,name=Key,proto3" json:"Key,omitempty"`
	Value []byte `protobuf:"bytes,3,opt,name=Value,proto3" json:"Value,omitempty"`
}

func (x *DoPluginReply) Reset() {
	*x = DoPluginReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_immplugin_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DoPluginReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DoPluginReply) ProtoMessage() {}

func (x *DoPluginReply) ProtoReflect() protoreflect.Message {
	mi := &file_proto_immplugin_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DoPluginReply.ProtoReflect.Descriptor instead.
func (*DoPluginReply) Descriptor() ([]byte, []int) {
	return file_proto_immplugin_proto_rawDescGZIP(), []int{1}
}

func (x *DoPluginReply) GetFunc() string {
	if x != nil {
		return x.Func
	}
	return ""
}

func (x *DoPluginReply) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *DoPluginReply) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

var File_proto_immplugin_proto protoreflect.FileDescriptor

var file_proto_immplugin_proto_rawDesc = []byte{
	0x0a, 0x15, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x69, 0x6d, 0x6d, 0x70, 0x6c, 0x75, 0x67, 0x69,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x69, 0x6d, 0x6d, 0x70, 0x6c, 0x75, 0x67,
	0x69, 0x6e, 0x22, 0x3f, 0x0a, 0x0f, 0x44, 0x6f, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x43, 0x72, 0x65, 0x61, 0x74, 0x6f, 0x72,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x43, 0x72, 0x65, 0x61, 0x74, 0x6f, 0x72, 0x12,
	0x12, 0x0a, 0x04, 0x41, 0x72, 0x67, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x04, 0x41,
	0x72, 0x67, 0x73, 0x22, 0x4b, 0x0a, 0x0d, 0x44, 0x6f, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x52,
	0x65, 0x70, 0x6c, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x46, 0x75, 0x6e, 0x63, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x46, 0x75, 0x6e, 0x63, 0x12, 0x10, 0x0a, 0x03, 0x4b, 0x65, 0x79, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x4b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x56, 0x61, 0x6c, 0x75, 0x65,
	0x32, 0x4f, 0x0a, 0x09, 0x49, 0x6d, 0x6d, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x12, 0x42, 0x0a,
	0x08, 0x44, 0x6f, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x12, 0x1a, 0x2e, 0x69, 0x6d, 0x6d, 0x70,
	0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2e, 0x44, 0x6f, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x69, 0x6d, 0x6d, 0x70, 0x6c, 0x75, 0x67, 0x69,
	0x6e, 0x2e, 0x44, 0x6f, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22,
	0x00, 0x42, 0x0d, 0x5a, 0x0b, 0x2e, 0x2f, 0x69, 0x6d, 0x6d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_immplugin_proto_rawDescOnce sync.Once
	file_proto_immplugin_proto_rawDescData = file_proto_immplugin_proto_rawDesc
)

func file_proto_immplugin_proto_rawDescGZIP() []byte {
	file_proto_immplugin_proto_rawDescOnce.Do(func() {
		file_proto_immplugin_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_immplugin_proto_rawDescData)
	})
	return file_proto_immplugin_proto_rawDescData
}

var file_proto_immplugin_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_proto_immplugin_proto_goTypes = []interface{}{
	(*DoPluginRequest)(nil), // 0: immplugin.DoPluginRequest
	(*DoPluginReply)(nil),   // 1: immplugin.DoPluginReply
}
var file_proto_immplugin_proto_depIdxs = []int32{
	0, // 0: immplugin.ImmPlugin.DoPlugin:input_type -> immplugin.DoPluginRequest
	1, // 1: immplugin.ImmPlugin.DoPlugin:output_type -> immplugin.DoPluginReply
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_proto_immplugin_proto_init() }
func file_proto_immplugin_proto_init() {
	if File_proto_immplugin_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_immplugin_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DoPluginRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_immplugin_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DoPluginReply); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_immplugin_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_immplugin_proto_goTypes,
		DependencyIndexes: file_proto_immplugin_proto_depIdxs,
		MessageInfos:      file_proto_immplugin_proto_msgTypes,
	}.Build()
	File_proto_immplugin_proto = out.File
	file_proto_immplugin_proto_rawDesc = nil
	file_proto_immplugin_proto_goTypes = nil
	file_proto_immplugin_proto_depIdxs = nil
}
