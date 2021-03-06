// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_ACQUIREPREAUTHTOKENREQUEST_TEO_H_
#define FLATBUFFERS_GENERATED_ACQUIREPREAUTHTOKENREQUEST_TEO_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {

struct AcquirePreAuthTokenRequest;
struct AcquirePreAuthTokenRequestBuilder;

struct AcquirePreAuthTokenRequest FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef AcquirePreAuthTokenRequestBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_USER_PUBKEY = 4
  };
  const flatbuffers::Vector<uint8_t> *user_pubkey() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_USER_PUBKEY);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_USER_PUBKEY) &&
           verifier.VerifyVector(user_pubkey()) &&
           verifier.EndTable();
  }
};

struct AcquirePreAuthTokenRequestBuilder {
  typedef AcquirePreAuthTokenRequest Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_user_pubkey(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> user_pubkey) {
    fbb_.AddOffset(AcquirePreAuthTokenRequest::VT_USER_PUBKEY, user_pubkey);
  }
  explicit AcquirePreAuthTokenRequestBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<AcquirePreAuthTokenRequest> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<AcquirePreAuthTokenRequest>(end);
    return o;
  }
};

inline flatbuffers::Offset<AcquirePreAuthTokenRequest> CreateAcquirePreAuthTokenRequest(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> user_pubkey = 0) {
  AcquirePreAuthTokenRequestBuilder builder_(_fbb);
  builder_.add_user_pubkey(user_pubkey);
  return builder_.Finish();
}

inline flatbuffers::Offset<AcquirePreAuthTokenRequest> CreateAcquirePreAuthTokenRequestDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *user_pubkey = nullptr) {
  auto user_pubkey__ = user_pubkey ? _fbb.CreateVector<uint8_t>(*user_pubkey) : 0;
  return teo::CreateAcquirePreAuthTokenRequest(
      _fbb,
      user_pubkey__);
}

inline const teo::AcquirePreAuthTokenRequest *GetAcquirePreAuthTokenRequest(const void *buf) {
  return flatbuffers::GetRoot<teo::AcquirePreAuthTokenRequest>(buf);
}

inline const teo::AcquirePreAuthTokenRequest *GetSizePrefixedAcquirePreAuthTokenRequest(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::AcquirePreAuthTokenRequest>(buf);
}

inline bool VerifyAcquirePreAuthTokenRequestBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::AcquirePreAuthTokenRequest>(nullptr);
}

inline bool VerifySizePrefixedAcquirePreAuthTokenRequestBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::AcquirePreAuthTokenRequest>(nullptr);
}

inline void FinishAcquirePreAuthTokenRequestBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::AcquirePreAuthTokenRequest> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedAcquirePreAuthTokenRequestBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::AcquirePreAuthTokenRequest> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_ACQUIREPREAUTHTOKENREQUEST_TEO_H_
