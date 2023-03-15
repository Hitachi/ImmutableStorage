// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: token/expectations.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_token_2fexpectations_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_token_2fexpectations_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3014000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3014000 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
#include <google/protobuf/timestamp.pb.h>
#include "token/transaction.pb.h"
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_token_2fexpectations_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_token_2fexpectations_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxiliaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[3]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const ::PROTOBUF_NAMESPACE_ID::uint32 offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_token_2fexpectations_2eproto;
namespace protos {
class PlainExpectation;
class PlainExpectationDefaultTypeInternal;
extern PlainExpectationDefaultTypeInternal _PlainExpectation_default_instance_;
class PlainTokenExpectation;
class PlainTokenExpectationDefaultTypeInternal;
extern PlainTokenExpectationDefaultTypeInternal _PlainTokenExpectation_default_instance_;
class TokenExpectation;
class TokenExpectationDefaultTypeInternal;
extern TokenExpectationDefaultTypeInternal _TokenExpectation_default_instance_;
}  // namespace protos
PROTOBUF_NAMESPACE_OPEN
template<> ::protos::PlainExpectation* Arena::CreateMaybeMessage<::protos::PlainExpectation>(Arena*);
template<> ::protos::PlainTokenExpectation* Arena::CreateMaybeMessage<::protos::PlainTokenExpectation>(Arena*);
template<> ::protos::TokenExpectation* Arena::CreateMaybeMessage<::protos::TokenExpectation>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace protos {

// ===================================================================

class TokenExpectation PROTOBUF_FINAL :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:protos.TokenExpectation) */ {
 public:
  inline TokenExpectation() : TokenExpectation(nullptr) {}
  virtual ~TokenExpectation();

  TokenExpectation(const TokenExpectation& from);
  TokenExpectation(TokenExpectation&& from) noexcept
    : TokenExpectation() {
    *this = ::std::move(from);
  }

  inline TokenExpectation& operator=(const TokenExpectation& from) {
    CopyFrom(from);
    return *this;
  }
  inline TokenExpectation& operator=(TokenExpectation&& from) noexcept {
    if (GetArena() == from.GetArena()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const TokenExpectation& default_instance();

  enum ExpectationCase {
    kPlainExpectation = 1,
    EXPECTATION_NOT_SET = 0,
  };

  static inline const TokenExpectation* internal_default_instance() {
    return reinterpret_cast<const TokenExpectation*>(
               &_TokenExpectation_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(TokenExpectation& a, TokenExpectation& b) {
    a.Swap(&b);
  }
  inline void Swap(TokenExpectation* other) {
    if (other == this) return;
    if (GetArena() == other->GetArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(TokenExpectation* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline TokenExpectation* New() const final {
    return CreateMaybeMessage<TokenExpectation>(nullptr);
  }

  TokenExpectation* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<TokenExpectation>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const TokenExpectation& from);
  void MergeFrom(const TokenExpectation& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(TokenExpectation* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "protos.TokenExpectation";
  }
  protected:
  explicit TokenExpectation(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_token_2fexpectations_2eproto);
    return ::descriptor_table_token_2fexpectations_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kPlainExpectationFieldNumber = 1,
  };
  // .protos.PlainExpectation plain_expectation = 1;
  bool has_plain_expectation() const;
  private:
  bool _internal_has_plain_expectation() const;
  public:
  void clear_plain_expectation();
  const ::protos::PlainExpectation& plain_expectation() const;
  ::protos::PlainExpectation* release_plain_expectation();
  ::protos::PlainExpectation* mutable_plain_expectation();
  void set_allocated_plain_expectation(::protos::PlainExpectation* plain_expectation);
  private:
  const ::protos::PlainExpectation& _internal_plain_expectation() const;
  ::protos::PlainExpectation* _internal_mutable_plain_expectation();
  public:
  void unsafe_arena_set_allocated_plain_expectation(
      ::protos::PlainExpectation* plain_expectation);
  ::protos::PlainExpectation* unsafe_arena_release_plain_expectation();

  void clear_Expectation();
  ExpectationCase Expectation_case() const;
  // @@protoc_insertion_point(class_scope:protos.TokenExpectation)
 private:
  class _Internal;
  void set_has_plain_expectation();

  inline bool has_Expectation() const;
  inline void clear_has_Expectation();

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  union ExpectationUnion {
    ExpectationUnion() {}
    ::protos::PlainExpectation* plain_expectation_;
  } Expectation_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  ::PROTOBUF_NAMESPACE_ID::uint32 _oneof_case_[1];

  friend struct ::TableStruct_token_2fexpectations_2eproto;
};
// -------------------------------------------------------------------

class PlainExpectation PROTOBUF_FINAL :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:protos.PlainExpectation) */ {
 public:
  inline PlainExpectation() : PlainExpectation(nullptr) {}
  virtual ~PlainExpectation();

  PlainExpectation(const PlainExpectation& from);
  PlainExpectation(PlainExpectation&& from) noexcept
    : PlainExpectation() {
    *this = ::std::move(from);
  }

  inline PlainExpectation& operator=(const PlainExpectation& from) {
    CopyFrom(from);
    return *this;
  }
  inline PlainExpectation& operator=(PlainExpectation&& from) noexcept {
    if (GetArena() == from.GetArena()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const PlainExpectation& default_instance();

  enum PayloadCase {
    kImportExpectation = 1,
    kTransferExpectation = 2,
    PAYLOAD_NOT_SET = 0,
  };

  static inline const PlainExpectation* internal_default_instance() {
    return reinterpret_cast<const PlainExpectation*>(
               &_PlainExpectation_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(PlainExpectation& a, PlainExpectation& b) {
    a.Swap(&b);
  }
  inline void Swap(PlainExpectation* other) {
    if (other == this) return;
    if (GetArena() == other->GetArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(PlainExpectation* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline PlainExpectation* New() const final {
    return CreateMaybeMessage<PlainExpectation>(nullptr);
  }

  PlainExpectation* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<PlainExpectation>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const PlainExpectation& from);
  void MergeFrom(const PlainExpectation& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(PlainExpectation* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "protos.PlainExpectation";
  }
  protected:
  explicit PlainExpectation(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_token_2fexpectations_2eproto);
    return ::descriptor_table_token_2fexpectations_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kImportExpectationFieldNumber = 1,
    kTransferExpectationFieldNumber = 2,
  };
  // .protos.PlainTokenExpectation import_expectation = 1;
  bool has_import_expectation() const;
  private:
  bool _internal_has_import_expectation() const;
  public:
  void clear_import_expectation();
  const ::protos::PlainTokenExpectation& import_expectation() const;
  ::protos::PlainTokenExpectation* release_import_expectation();
  ::protos::PlainTokenExpectation* mutable_import_expectation();
  void set_allocated_import_expectation(::protos::PlainTokenExpectation* import_expectation);
  private:
  const ::protos::PlainTokenExpectation& _internal_import_expectation() const;
  ::protos::PlainTokenExpectation* _internal_mutable_import_expectation();
  public:
  void unsafe_arena_set_allocated_import_expectation(
      ::protos::PlainTokenExpectation* import_expectation);
  ::protos::PlainTokenExpectation* unsafe_arena_release_import_expectation();

  // .protos.PlainTokenExpectation transfer_expectation = 2;
  bool has_transfer_expectation() const;
  private:
  bool _internal_has_transfer_expectation() const;
  public:
  void clear_transfer_expectation();
  const ::protos::PlainTokenExpectation& transfer_expectation() const;
  ::protos::PlainTokenExpectation* release_transfer_expectation();
  ::protos::PlainTokenExpectation* mutable_transfer_expectation();
  void set_allocated_transfer_expectation(::protos::PlainTokenExpectation* transfer_expectation);
  private:
  const ::protos::PlainTokenExpectation& _internal_transfer_expectation() const;
  ::protos::PlainTokenExpectation* _internal_mutable_transfer_expectation();
  public:
  void unsafe_arena_set_allocated_transfer_expectation(
      ::protos::PlainTokenExpectation* transfer_expectation);
  ::protos::PlainTokenExpectation* unsafe_arena_release_transfer_expectation();

  void clear_payload();
  PayloadCase payload_case() const;
  // @@protoc_insertion_point(class_scope:protos.PlainExpectation)
 private:
  class _Internal;
  void set_has_import_expectation();
  void set_has_transfer_expectation();

  inline bool has_payload() const;
  inline void clear_has_payload();

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  union PayloadUnion {
    PayloadUnion() {}
    ::protos::PlainTokenExpectation* import_expectation_;
    ::protos::PlainTokenExpectation* transfer_expectation_;
  } payload_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  ::PROTOBUF_NAMESPACE_ID::uint32 _oneof_case_[1];

  friend struct ::TableStruct_token_2fexpectations_2eproto;
};
// -------------------------------------------------------------------

class PlainTokenExpectation PROTOBUF_FINAL :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:protos.PlainTokenExpectation) */ {
 public:
  inline PlainTokenExpectation() : PlainTokenExpectation(nullptr) {}
  virtual ~PlainTokenExpectation();

  PlainTokenExpectation(const PlainTokenExpectation& from);
  PlainTokenExpectation(PlainTokenExpectation&& from) noexcept
    : PlainTokenExpectation() {
    *this = ::std::move(from);
  }

  inline PlainTokenExpectation& operator=(const PlainTokenExpectation& from) {
    CopyFrom(from);
    return *this;
  }
  inline PlainTokenExpectation& operator=(PlainTokenExpectation&& from) noexcept {
    if (GetArena() == from.GetArena()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const PlainTokenExpectation& default_instance();

  static inline const PlainTokenExpectation* internal_default_instance() {
    return reinterpret_cast<const PlainTokenExpectation*>(
               &_PlainTokenExpectation_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    2;

  friend void swap(PlainTokenExpectation& a, PlainTokenExpectation& b) {
    a.Swap(&b);
  }
  inline void Swap(PlainTokenExpectation* other) {
    if (other == this) return;
    if (GetArena() == other->GetArena()) {
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(PlainTokenExpectation* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline PlainTokenExpectation* New() const final {
    return CreateMaybeMessage<PlainTokenExpectation>(nullptr);
  }

  PlainTokenExpectation* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<PlainTokenExpectation>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const PlainTokenExpectation& from);
  void MergeFrom(const PlainTokenExpectation& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(PlainTokenExpectation* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "protos.PlainTokenExpectation";
  }
  protected:
  explicit PlainTokenExpectation(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_token_2fexpectations_2eproto);
    return ::descriptor_table_token_2fexpectations_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kOutputsFieldNumber = 1,
  };
  // repeated .PlainOutput outputs = 1;
  int outputs_size() const;
  private:
  int _internal_outputs_size() const;
  public:
  void clear_outputs();
  ::PlainOutput* mutable_outputs(int index);
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::PlainOutput >*
      mutable_outputs();
  private:
  const ::PlainOutput& _internal_outputs(int index) const;
  ::PlainOutput* _internal_add_outputs();
  public:
  const ::PlainOutput& outputs(int index) const;
  ::PlainOutput* add_outputs();
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::PlainOutput >&
      outputs() const;

  // @@protoc_insertion_point(class_scope:protos.PlainTokenExpectation)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::PlainOutput > outputs_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_token_2fexpectations_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// TokenExpectation

// .protos.PlainExpectation plain_expectation = 1;
inline bool TokenExpectation::_internal_has_plain_expectation() const {
  return Expectation_case() == kPlainExpectation;
}
inline bool TokenExpectation::has_plain_expectation() const {
  return _internal_has_plain_expectation();
}
inline void TokenExpectation::set_has_plain_expectation() {
  _oneof_case_[0] = kPlainExpectation;
}
inline void TokenExpectation::clear_plain_expectation() {
  if (_internal_has_plain_expectation()) {
    if (GetArena() == nullptr) {
      delete Expectation_.plain_expectation_;
    }
    clear_has_Expectation();
  }
}
inline ::protos::PlainExpectation* TokenExpectation::release_plain_expectation() {
  // @@protoc_insertion_point(field_release:protos.TokenExpectation.plain_expectation)
  if (_internal_has_plain_expectation()) {
    clear_has_Expectation();
      ::protos::PlainExpectation* temp = Expectation_.plain_expectation_;
    if (GetArena() != nullptr) {
      temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
    }
    Expectation_.plain_expectation_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline const ::protos::PlainExpectation& TokenExpectation::_internal_plain_expectation() const {
  return _internal_has_plain_expectation()
      ? *Expectation_.plain_expectation_
      : reinterpret_cast< ::protos::PlainExpectation&>(::protos::_PlainExpectation_default_instance_);
}
inline const ::protos::PlainExpectation& TokenExpectation::plain_expectation() const {
  // @@protoc_insertion_point(field_get:protos.TokenExpectation.plain_expectation)
  return _internal_plain_expectation();
}
inline ::protos::PlainExpectation* TokenExpectation::unsafe_arena_release_plain_expectation() {
  // @@protoc_insertion_point(field_unsafe_arena_release:protos.TokenExpectation.plain_expectation)
  if (_internal_has_plain_expectation()) {
    clear_has_Expectation();
    ::protos::PlainExpectation* temp = Expectation_.plain_expectation_;
    Expectation_.plain_expectation_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline void TokenExpectation::unsafe_arena_set_allocated_plain_expectation(::protos::PlainExpectation* plain_expectation) {
  clear_Expectation();
  if (plain_expectation) {
    set_has_plain_expectation();
    Expectation_.plain_expectation_ = plain_expectation;
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:protos.TokenExpectation.plain_expectation)
}
inline ::protos::PlainExpectation* TokenExpectation::_internal_mutable_plain_expectation() {
  if (!_internal_has_plain_expectation()) {
    clear_Expectation();
    set_has_plain_expectation();
    Expectation_.plain_expectation_ = CreateMaybeMessage< ::protos::PlainExpectation >(GetArena());
  }
  return Expectation_.plain_expectation_;
}
inline ::protos::PlainExpectation* TokenExpectation::mutable_plain_expectation() {
  // @@protoc_insertion_point(field_mutable:protos.TokenExpectation.plain_expectation)
  return _internal_mutable_plain_expectation();
}

inline bool TokenExpectation::has_Expectation() const {
  return Expectation_case() != EXPECTATION_NOT_SET;
}
inline void TokenExpectation::clear_has_Expectation() {
  _oneof_case_[0] = EXPECTATION_NOT_SET;
}
inline TokenExpectation::ExpectationCase TokenExpectation::Expectation_case() const {
  return TokenExpectation::ExpectationCase(_oneof_case_[0]);
}
// -------------------------------------------------------------------

// PlainExpectation

// .protos.PlainTokenExpectation import_expectation = 1;
inline bool PlainExpectation::_internal_has_import_expectation() const {
  return payload_case() == kImportExpectation;
}
inline bool PlainExpectation::has_import_expectation() const {
  return _internal_has_import_expectation();
}
inline void PlainExpectation::set_has_import_expectation() {
  _oneof_case_[0] = kImportExpectation;
}
inline void PlainExpectation::clear_import_expectation() {
  if (_internal_has_import_expectation()) {
    if (GetArena() == nullptr) {
      delete payload_.import_expectation_;
    }
    clear_has_payload();
  }
}
inline ::protos::PlainTokenExpectation* PlainExpectation::release_import_expectation() {
  // @@protoc_insertion_point(field_release:protos.PlainExpectation.import_expectation)
  if (_internal_has_import_expectation()) {
    clear_has_payload();
      ::protos::PlainTokenExpectation* temp = payload_.import_expectation_;
    if (GetArena() != nullptr) {
      temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
    }
    payload_.import_expectation_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline const ::protos::PlainTokenExpectation& PlainExpectation::_internal_import_expectation() const {
  return _internal_has_import_expectation()
      ? *payload_.import_expectation_
      : reinterpret_cast< ::protos::PlainTokenExpectation&>(::protos::_PlainTokenExpectation_default_instance_);
}
inline const ::protos::PlainTokenExpectation& PlainExpectation::import_expectation() const {
  // @@protoc_insertion_point(field_get:protos.PlainExpectation.import_expectation)
  return _internal_import_expectation();
}
inline ::protos::PlainTokenExpectation* PlainExpectation::unsafe_arena_release_import_expectation() {
  // @@protoc_insertion_point(field_unsafe_arena_release:protos.PlainExpectation.import_expectation)
  if (_internal_has_import_expectation()) {
    clear_has_payload();
    ::protos::PlainTokenExpectation* temp = payload_.import_expectation_;
    payload_.import_expectation_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline void PlainExpectation::unsafe_arena_set_allocated_import_expectation(::protos::PlainTokenExpectation* import_expectation) {
  clear_payload();
  if (import_expectation) {
    set_has_import_expectation();
    payload_.import_expectation_ = import_expectation;
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:protos.PlainExpectation.import_expectation)
}
inline ::protos::PlainTokenExpectation* PlainExpectation::_internal_mutable_import_expectation() {
  if (!_internal_has_import_expectation()) {
    clear_payload();
    set_has_import_expectation();
    payload_.import_expectation_ = CreateMaybeMessage< ::protos::PlainTokenExpectation >(GetArena());
  }
  return payload_.import_expectation_;
}
inline ::protos::PlainTokenExpectation* PlainExpectation::mutable_import_expectation() {
  // @@protoc_insertion_point(field_mutable:protos.PlainExpectation.import_expectation)
  return _internal_mutable_import_expectation();
}

// .protos.PlainTokenExpectation transfer_expectation = 2;
inline bool PlainExpectation::_internal_has_transfer_expectation() const {
  return payload_case() == kTransferExpectation;
}
inline bool PlainExpectation::has_transfer_expectation() const {
  return _internal_has_transfer_expectation();
}
inline void PlainExpectation::set_has_transfer_expectation() {
  _oneof_case_[0] = kTransferExpectation;
}
inline void PlainExpectation::clear_transfer_expectation() {
  if (_internal_has_transfer_expectation()) {
    if (GetArena() == nullptr) {
      delete payload_.transfer_expectation_;
    }
    clear_has_payload();
  }
}
inline ::protos::PlainTokenExpectation* PlainExpectation::release_transfer_expectation() {
  // @@protoc_insertion_point(field_release:protos.PlainExpectation.transfer_expectation)
  if (_internal_has_transfer_expectation()) {
    clear_has_payload();
      ::protos::PlainTokenExpectation* temp = payload_.transfer_expectation_;
    if (GetArena() != nullptr) {
      temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
    }
    payload_.transfer_expectation_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline const ::protos::PlainTokenExpectation& PlainExpectation::_internal_transfer_expectation() const {
  return _internal_has_transfer_expectation()
      ? *payload_.transfer_expectation_
      : reinterpret_cast< ::protos::PlainTokenExpectation&>(::protos::_PlainTokenExpectation_default_instance_);
}
inline const ::protos::PlainTokenExpectation& PlainExpectation::transfer_expectation() const {
  // @@protoc_insertion_point(field_get:protos.PlainExpectation.transfer_expectation)
  return _internal_transfer_expectation();
}
inline ::protos::PlainTokenExpectation* PlainExpectation::unsafe_arena_release_transfer_expectation() {
  // @@protoc_insertion_point(field_unsafe_arena_release:protos.PlainExpectation.transfer_expectation)
  if (_internal_has_transfer_expectation()) {
    clear_has_payload();
    ::protos::PlainTokenExpectation* temp = payload_.transfer_expectation_;
    payload_.transfer_expectation_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline void PlainExpectation::unsafe_arena_set_allocated_transfer_expectation(::protos::PlainTokenExpectation* transfer_expectation) {
  clear_payload();
  if (transfer_expectation) {
    set_has_transfer_expectation();
    payload_.transfer_expectation_ = transfer_expectation;
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:protos.PlainExpectation.transfer_expectation)
}
inline ::protos::PlainTokenExpectation* PlainExpectation::_internal_mutable_transfer_expectation() {
  if (!_internal_has_transfer_expectation()) {
    clear_payload();
    set_has_transfer_expectation();
    payload_.transfer_expectation_ = CreateMaybeMessage< ::protos::PlainTokenExpectation >(GetArena());
  }
  return payload_.transfer_expectation_;
}
inline ::protos::PlainTokenExpectation* PlainExpectation::mutable_transfer_expectation() {
  // @@protoc_insertion_point(field_mutable:protos.PlainExpectation.transfer_expectation)
  return _internal_mutable_transfer_expectation();
}

inline bool PlainExpectation::has_payload() const {
  return payload_case() != PAYLOAD_NOT_SET;
}
inline void PlainExpectation::clear_has_payload() {
  _oneof_case_[0] = PAYLOAD_NOT_SET;
}
inline PlainExpectation::PayloadCase PlainExpectation::payload_case() const {
  return PlainExpectation::PayloadCase(_oneof_case_[0]);
}
// -------------------------------------------------------------------

// PlainTokenExpectation

// repeated .PlainOutput outputs = 1;
inline int PlainTokenExpectation::_internal_outputs_size() const {
  return outputs_.size();
}
inline int PlainTokenExpectation::outputs_size() const {
  return _internal_outputs_size();
}
inline ::PlainOutput* PlainTokenExpectation::mutable_outputs(int index) {
  // @@protoc_insertion_point(field_mutable:protos.PlainTokenExpectation.outputs)
  return outputs_.Mutable(index);
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::PlainOutput >*
PlainTokenExpectation::mutable_outputs() {
  // @@protoc_insertion_point(field_mutable_list:protos.PlainTokenExpectation.outputs)
  return &outputs_;
}
inline const ::PlainOutput& PlainTokenExpectation::_internal_outputs(int index) const {
  return outputs_.Get(index);
}
inline const ::PlainOutput& PlainTokenExpectation::outputs(int index) const {
  // @@protoc_insertion_point(field_get:protos.PlainTokenExpectation.outputs)
  return _internal_outputs(index);
}
inline ::PlainOutput* PlainTokenExpectation::_internal_add_outputs() {
  return outputs_.Add();
}
inline ::PlainOutput* PlainTokenExpectation::add_outputs() {
  // @@protoc_insertion_point(field_add:protos.PlainTokenExpectation.outputs)
  return _internal_add_outputs();
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::PlainOutput >&
PlainTokenExpectation::outputs() const {
  // @@protoc_insertion_point(field_list:protos.PlainTokenExpectation.outputs)
  return outputs_;
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------

// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace protos

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_token_2fexpectations_2eproto
