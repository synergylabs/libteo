// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_CLAIMDEVICEREQUEST_TEO_H_
#define FLATBUFFERS_GENERATED_CLAIMDEVICEREQUEST_TEO_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {

struct ClaimDeviceRequest;
struct ClaimDeviceRequestBuilder;

struct ClaimDeviceRequest FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef ClaimDeviceRequestBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NONCE = 4,
    VT_CIPHERTEXT = 6,
    VT_GROUP_MODE = 8
  };
  const flatbuffers::Vector<uint8_t> *nonce() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_NONCE);
  }
  const flatbuffers::Vector<uint8_t> *ciphertext() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_CIPHERTEXT);
  }
  int32_t group_mode() const {
    return GetField<int32_t>(VT_GROUP_MODE, 0);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_NONCE) &&
           verifier.VerifyVector(nonce()) &&
           VerifyOffset(verifier, VT_CIPHERTEXT) &&
           verifier.VerifyVector(ciphertext()) &&
           VerifyField<int32_t>(verifier, VT_GROUP_MODE) &&
           verifier.EndTable();
  }
};

struct ClaimDeviceRequestBuilder {
  typedef ClaimDeviceRequest Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_nonce(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> nonce) {
    fbb_.AddOffset(ClaimDeviceRequest::VT_NONCE, nonce);
  }
  void add_ciphertext(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> ciphertext) {
    fbb_.AddOffset(ClaimDeviceRequest::VT_CIPHERTEXT, ciphertext);
  }
  void add_group_mode(int32_t group_mode) {
    fbb_.AddElement<int32_t>(ClaimDeviceRequest::VT_GROUP_MODE, group_mode, 0);
  }
  explicit ClaimDeviceRequestBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<ClaimDeviceRequest> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<ClaimDeviceRequest>(end);
    return o;
  }
};

inline flatbuffers::Offset<ClaimDeviceRequest> CreateClaimDeviceRequest(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> nonce = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> ciphertext = 0,
    int32_t group_mode = 0) {
  ClaimDeviceRequestBuilder builder_(_fbb);
  builder_.add_group_mode(group_mode);
  builder_.add_ciphertext(ciphertext);
  builder_.add_nonce(nonce);
  return builder_.Finish();
}

inline flatbuffers::Offset<ClaimDeviceRequest> CreateClaimDeviceRequestDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *nonce = nullptr,
    const std::vector<uint8_t> *ciphertext = nullptr,
    int32_t group_mode = 0) {
  auto nonce__ = nonce ? _fbb.CreateVector<uint8_t>(*nonce) : 0;
  auto ciphertext__ = ciphertext ? _fbb.CreateVector<uint8_t>(*ciphertext) : 0;
  return teo::CreateClaimDeviceRequest(
      _fbb,
      nonce__,
      ciphertext__,
      group_mode);
}

inline const teo::ClaimDeviceRequest *GetClaimDeviceRequest(const void *buf) {
  return flatbuffers::GetRoot<teo::ClaimDeviceRequest>(buf);
}

inline const teo::ClaimDeviceRequest *GetSizePrefixedClaimDeviceRequest(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::ClaimDeviceRequest>(buf);
}

inline bool VerifyClaimDeviceRequestBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::ClaimDeviceRequest>(nullptr);
}

inline bool VerifySizePrefixedClaimDeviceRequestBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::ClaimDeviceRequest>(nullptr);
}

inline void FinishClaimDeviceRequestBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::ClaimDeviceRequest> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedClaimDeviceRequestBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::ClaimDeviceRequest> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_CLAIMDEVICEREQUEST_TEO_H_
