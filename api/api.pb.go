// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: api/api.proto

package api

import (
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

type Signature struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Payload         string `protobuf:"bytes,1,opt,name=Payload,proto3" json:"Payload,omitempty"`
	Base64Signature string `protobuf:"bytes,2,opt,name=Base64Signature,proto3" json:"Base64Signature,omitempty"`
}

func (x *Signature) Reset() {
	*x = Signature{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Signature) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Signature) ProtoMessage() {}

func (x *Signature) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Signature.ProtoReflect.Descriptor instead.
func (*Signature) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{0}
}

func (x *Signature) GetPayload() string {
	if x != nil {
		return x.Payload
	}
	return ""
}

func (x *Signature) GetBase64Signature() string {
	if x != nil {
		return x.Base64Signature
	}
	return ""
}

type ImageSignaturesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ImageReference string `protobuf:"bytes,1,opt,name=ImageReference,proto3" json:"ImageReference,omitempty"`
}

func (x *ImageSignaturesRequest) Reset() {
	*x = ImageSignaturesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImageSignaturesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImageSignaturesRequest) ProtoMessage() {}

func (x *ImageSignaturesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImageSignaturesRequest.ProtoReflect.Descriptor instead.
func (*ImageSignaturesRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{1}
}

func (x *ImageSignaturesRequest) GetImageReference() string {
	if x != nil {
		return x.ImageReference
	}
	return ""
}

type ImageSignaturesReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signatures []*Signature `protobuf:"bytes,1,rep,name=Signatures,proto3" json:"Signatures,omitempty"`
}

func (x *ImageSignaturesReply) Reset() {
	*x = ImageSignaturesReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImageSignaturesReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImageSignaturesReply) ProtoMessage() {}

func (x *ImageSignaturesReply) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImageSignaturesReply.ProtoReflect.Descriptor instead.
func (*ImageSignaturesReply) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{2}
}

func (x *ImageSignaturesReply) GetSignatures() []*Signature {
	if x != nil {
		return x.Signatures
	}
	return nil
}

type ImageSignedRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ImageReference string       `protobuf:"bytes,1,opt,name=ImageReference,proto3" json:"ImageReference,omitempty"`
	Signatures     []*Signature `protobuf:"bytes,2,rep,name=Signatures,proto3" json:"Signatures,omitempty"`
	PublicKey      string       `protobuf:"bytes,3,opt,name=PublicKey,proto3" json:"PublicKey,omitempty"`
}

func (x *ImageSignedRequest) Reset() {
	*x = ImageSignedRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImageSignedRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImageSignedRequest) ProtoMessage() {}

func (x *ImageSignedRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImageSignedRequest.ProtoReflect.Descriptor instead.
func (*ImageSignedRequest) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{3}
}

func (x *ImageSignedRequest) GetImageReference() string {
	if x != nil {
		return x.ImageReference
	}
	return ""
}

func (x *ImageSignedRequest) GetSignatures() []*Signature {
	if x != nil {
		return x.Signatures
	}
	return nil
}

func (x *ImageSignedRequest) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

type ImageSignedReply struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ImageSigned bool `protobuf:"varint,1,opt,name=ImageSigned,proto3" json:"ImageSigned,omitempty"`
}

func (x *ImageSignedReply) Reset() {
	*x = ImageSignedReply{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_api_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ImageSignedReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ImageSignedReply) ProtoMessage() {}

func (x *ImageSignedReply) ProtoReflect() protoreflect.Message {
	mi := &file_api_api_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ImageSignedReply.ProtoReflect.Descriptor instead.
func (*ImageSignedReply) Descriptor() ([]byte, []int) {
	return file_api_api_proto_rawDescGZIP(), []int{4}
}

func (x *ImageSignedReply) GetImageSigned() bool {
	if x != nil {
		return x.ImageSigned
	}
	return false
}

var File_api_api_proto protoreflect.FileDescriptor

var file_api_api_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x03, 0x61, 0x70, 0x69, 0x22, 0x4f, 0x0a, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x12, 0x18, 0x0a, 0x07, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x28, 0x0a, 0x0f, 0x42,
	0x61, 0x73, 0x65, 0x36, 0x34, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x42, 0x61, 0x73, 0x65, 0x36, 0x34, 0x53, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x40, 0x0a, 0x16, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x26, 0x0a, 0x0e, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x52, 0x65,
	0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x22, 0x46, 0x0a, 0x14, 0x49, 0x6d, 0x61, 0x67, 0x65,
	0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12,
	0x2e, 0x0a, 0x0a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x52, 0x0a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x22,
	0x8a, 0x01, 0x0a, 0x12, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x26, 0x0a, 0x0e, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x52,
	0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e,
	0x49, 0x6d, 0x61, 0x67, 0x65, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x12, 0x2e,
	0x0a, 0x0a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x52, 0x0a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x12, 0x1c,
	0x0a, 0x09, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x34, 0x0a, 0x10,
	0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x52, 0x65, 0x70, 0x6c, 0x79,
	0x12, 0x20, 0x0a, 0x0b, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67, 0x6e,
	0x65, 0x64, 0x32, 0xa5, 0x01, 0x0a, 0x15, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x4b, 0x0a, 0x0f,
	0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x12,
	0x1b, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x61,
	0x70, 0x69, 0x2e, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x73, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x12, 0x3f, 0x0a, 0x0b, 0x49, 0x6d, 0x61,
	0x67, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x12, 0x17, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x49,
	0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x15, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x53, 0x69, 0x67,
	0x6e, 0x65, 0x64, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x42, 0x30, 0x5a, 0x2e, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x6c, 0x6f, 0x70, 0x65, 0x7a, 0x2d,
	0x73, 0x75, 0x73, 0x65, 0x2f, 0x63, 0x6f, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x76, 0x65, 0x72, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_api_proto_rawDescOnce sync.Once
	file_api_api_proto_rawDescData = file_api_api_proto_rawDesc
)

func file_api_api_proto_rawDescGZIP() []byte {
	file_api_api_proto_rawDescOnce.Do(func() {
		file_api_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_api_proto_rawDescData)
	})
	return file_api_api_proto_rawDescData
}

var file_api_api_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_api_api_proto_goTypes = []interface{}{
	(*Signature)(nil),              // 0: api.Signature
	(*ImageSignaturesRequest)(nil), // 1: api.ImageSignaturesRequest
	(*ImageSignaturesReply)(nil),   // 2: api.ImageSignaturesReply
	(*ImageSignedRequest)(nil),     // 3: api.ImageSignedRequest
	(*ImageSignedReply)(nil),       // 4: api.ImageSignedReply
}
var file_api_api_proto_depIdxs = []int32{
	0, // 0: api.ImageSignaturesReply.Signatures:type_name -> api.Signature
	0, // 1: api.ImageSignedRequest.Signatures:type_name -> api.Signature
	1, // 2: api.SignatureVerification.ImageSignatures:input_type -> api.ImageSignaturesRequest
	3, // 3: api.SignatureVerification.ImageSigned:input_type -> api.ImageSignedRequest
	2, // 4: api.SignatureVerification.ImageSignatures:output_type -> api.ImageSignaturesReply
	4, // 5: api.SignatureVerification.ImageSigned:output_type -> api.ImageSignedReply
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_api_api_proto_init() }
func file_api_api_proto_init() {
	if File_api_api_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Signature); i {
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
		file_api_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImageSignaturesRequest); i {
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
		file_api_api_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImageSignaturesReply); i {
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
		file_api_api_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImageSignedRequest); i {
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
		file_api_api_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ImageSignedReply); i {
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
			RawDescriptor: file_api_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_api_proto_goTypes,
		DependencyIndexes: file_api_api_proto_depIdxs,
		MessageInfos:      file_api_api_proto_msgTypes,
	}.Build()
	File_api_api_proto = out.File
	file_api_api_proto_rawDesc = nil
	file_api_api_proto_goTypes = nil
	file_api_api_proto_depIdxs = nil
}
