// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: libimmds.proto

#include "libimmds.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
namespace libimmds {
class TxIdListDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<TxIdList> _instance;
} _TxIdList_default_instance_;
}  // namespace libimmds
static void InitDefaultsscc_info_TxIdList_libimmds_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::libimmds::_TxIdList_default_instance_;
    new (ptr) ::libimmds::TxIdList();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::libimmds::TxIdList::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<0> scc_info_TxIdList_libimmds_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, 0, InitDefaultsscc_info_TxIdList_libimmds_2eproto}, {}};

static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_libimmds_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_libimmds_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_libimmds_2eproto = nullptr;

const ::PROTOBUF_NAMESPACE_ID::uint32 TableStruct_libimmds_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::libimmds::TxIdList, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  PROTOBUF_FIELD_OFFSET(::libimmds::TxIdList, txid_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::libimmds::TxIdList)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::libimmds::_TxIdList_default_instance_),
};

const char descriptor_table_protodef_libimmds_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\016libimmds.proto\022\010libimmds\"\030\n\010TxIdList\022\014"
  "\n\004TxID\030\001 \003(\tB\014Z\n./libimmdsb\006proto3"
  ;
static const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable*const descriptor_table_libimmds_2eproto_deps[1] = {
};
static ::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase*const descriptor_table_libimmds_2eproto_sccs[1] = {
  &scc_info_TxIdList_libimmds_2eproto.base,
};
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_libimmds_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_libimmds_2eproto = {
  false, false, descriptor_table_protodef_libimmds_2eproto, "libimmds.proto", 74,
  &descriptor_table_libimmds_2eproto_once, descriptor_table_libimmds_2eproto_sccs, descriptor_table_libimmds_2eproto_deps, 1, 0,
  schemas, file_default_instances, TableStruct_libimmds_2eproto::offsets,
  file_level_metadata_libimmds_2eproto, 1, file_level_enum_descriptors_libimmds_2eproto, file_level_service_descriptors_libimmds_2eproto,
};

// Force running AddDescriptors() at dynamic initialization time.
static bool dynamic_init_dummy_libimmds_2eproto = (static_cast<void>(::PROTOBUF_NAMESPACE_ID::internal::AddDescriptors(&descriptor_table_libimmds_2eproto)), true);
namespace libimmds {

// ===================================================================

void TxIdList::InitAsDefaultInstance() {
}
class TxIdList::_Internal {
 public:
};

TxIdList::TxIdList(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena),
  txid_(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:libimmds.TxIdList)
}
TxIdList::TxIdList(const TxIdList& from)
  : ::PROTOBUF_NAMESPACE_ID::Message(),
      txid_(from.txid_) {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:libimmds.TxIdList)
}

void TxIdList::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_TxIdList_libimmds_2eproto.base);
}

TxIdList::~TxIdList() {
  // @@protoc_insertion_point(destructor:libimmds.TxIdList)
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

void TxIdList::SharedDtor() {
  GOOGLE_DCHECK(GetArena() == nullptr);
}

void TxIdList::ArenaDtor(void* object) {
  TxIdList* _this = reinterpret_cast< TxIdList* >(object);
  (void)_this;
}
void TxIdList::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void TxIdList::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const TxIdList& TxIdList::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_TxIdList_libimmds_2eproto.base);
  return *internal_default_instance();
}


void TxIdList::Clear() {
// @@protoc_insertion_point(message_clear_start:libimmds.TxIdList)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  txid_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* TxIdList::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  ::PROTOBUF_NAMESPACE_ID::Arena* arena = GetArena(); (void)arena;
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // repeated string TxID = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          ptr -= 1;
          do {
            ptr += 1;
            auto str = _internal_add_txid();
            ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
            CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, "libimmds.TxIdList.TxID"));
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<10>(ptr));
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag & 7) == 4 || tag == 0) {
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* TxIdList::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:libimmds.TxIdList)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated string TxID = 1;
  for (int i = 0, n = this->_internal_txid_size(); i < n; i++) {
    const auto& s = this->_internal_txid(i);
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      s.data(), static_cast<int>(s.length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "libimmds.TxIdList.TxID");
    target = stream->WriteString(1, s, target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:libimmds.TxIdList)
  return target;
}

size_t TxIdList::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:libimmds.TxIdList)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated string TxID = 1;
  total_size += 1 *
      ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(txid_.size());
  for (int i = 0, n = txid_.size(); i < n; i++) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
      txid_.Get(i));
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    return ::PROTOBUF_NAMESPACE_ID::internal::ComputeUnknownFieldsSize(
        _internal_metadata_, total_size, &_cached_size_);
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void TxIdList::MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:libimmds.TxIdList)
  GOOGLE_DCHECK_NE(&from, this);
  const TxIdList* source =
      ::PROTOBUF_NAMESPACE_ID::DynamicCastToGenerated<TxIdList>(
          &from);
  if (source == nullptr) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:libimmds.TxIdList)
    ::PROTOBUF_NAMESPACE_ID::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:libimmds.TxIdList)
    MergeFrom(*source);
  }
}

void TxIdList::MergeFrom(const TxIdList& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:libimmds.TxIdList)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  txid_.MergeFrom(from.txid_);
}

void TxIdList::CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:libimmds.TxIdList)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void TxIdList::CopyFrom(const TxIdList& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:libimmds.TxIdList)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool TxIdList::IsInitialized() const {
  return true;
}

void TxIdList::InternalSwap(TxIdList* other) {
  using std::swap;
  _internal_metadata_.Swap<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(&other->_internal_metadata_);
  txid_.InternalSwap(&other->txid_);
}

::PROTOBUF_NAMESPACE_ID::Metadata TxIdList::GetMetadata() const {
  return GetMetadataStatic();
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace libimmds
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::libimmds::TxIdList* Arena::CreateMaybeMessage< ::libimmds::TxIdList >(Arena* arena) {
  return Arena::CreateMessageInternal< ::libimmds::TxIdList >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
