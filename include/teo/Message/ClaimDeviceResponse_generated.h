// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_CLAIMDEVICERESPONSE_TEO_H_
#define FLATBUFFERS_GENERATED_CLAIMDEVICERESPONSE_TEO_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {

struct ClaimDeviceResponse;
struct ClaimDeviceResponseBuilder;

struct ClaimDeviceResponse FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef ClaimDeviceResponseBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_STATUS = 4,
    VT_RESPONSE_NONCE = 6,
    VT_CHALLENGE_RESPONSE_ENCRYPTED = 8
  };
  bool status() const {
    return GetField<uint8_t>(VT_STATUS, 0) != 0;
  }
  const flatbuffers::Vector<uint8_t> *response_nonce() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_RESPONSE_NONCE);
  }
  const flatbuffers::Vector<uint8_t> *challenge_response_encrypted() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_CHALLENGE_RESPONSE_ENCRYPTED);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint8_t>(verifier, VT_STATUS) &&
           VerifyOffset(verifier, VT_RESPONSE_NONCE) &&
           verifier.VerifyVector(response_nonce()) &&
           VerifyOffset(verifier, VT_CHALLENGE_RESPONSE_ENCRYPTED) &&
           verifier.VerifyVector(challenge_response_encrypted()) &&
           verifier.EndTable();
  }
};

struct ClaimDeviceResponseBuilder {
  typedef ClaimDeviceResponse Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_status(bool status) {
    fbb_.AddElement<uint8_t>(ClaimDeviceResponse::VT_STATUS, static_cast<uint8_t>(status), 0);
  }
  void add_response_nonce(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> response_nonce) {
    fbb_.AddOffset(ClaimDeviceResponse::VT_RESPONSE_NONCE, response_nonce);
  }
  void add_challenge_response_encrypted(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> challenge_response_encrypted) {
    fbb_.AddOffset(ClaimDeviceResponse::VT_CHALLENGE_RESPONSE_ENCRYPTED, challenge_response_encrypted);
  }
  explicit ClaimDeviceResponseBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<ClaimDeviceResponse> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<ClaimDeviceResponse>(end);
    return o;
  }
};

inline flatbuffers::Offset<ClaimDeviceResponse> CreateClaimDeviceResponse(
    flatbuffers::FlatBufferBuilder &_fbb,
    bool status = false,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> response_nonce = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> challenge_response_encrypted = 0) {
  ClaimDeviceResponseBuilder builder_(_fbb);
  builder_.add_challenge_response_encrypted(challenge_response_encrypted);
  builder_.add_response_nonce(response_nonce);
  builder_.add_status(status);
  return builder_.Finish();
}

inline flatbuffers::Offset<ClaimDeviceResponse> CreateClaimDeviceResponseDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    bool status = false,
    const std::vector<uint8_t> *response_nonce = nullptr,
    const std::vector<uint8_t> *challenge_response_encrypted = nullptr) {
  auto response_nonce__ = response_nonce ? _fbb.CreateVector<uint8_t>(*response_nonce) : 0;
  auto challenge_response_encrypted__ = challenge_response_encrypted ? _fbb.CreateVector<uint8_t>(*challenge_response_encrypted) : 0;
  return teo::CreateClaimDeviceResponse(
      _fbb,
      status,
      response_nonce__,
      challenge_response_encrypted__);
}

inline const teo::ClaimDeviceResponse *GetClaimDeviceResponse(const void *buf) {
  return flatbuffers::GetRoot<teo::ClaimDeviceResponse>(buf);
}

inline const teo::ClaimDeviceResponse *GetSizePrefixedClaimDeviceResponse(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::ClaimDeviceResponse>(buf);
}

inline bool VerifyClaimDeviceResponseBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::ClaimDeviceResponse>(nullptr);
}

inline bool VerifySizePrefixedClaimDeviceResponseBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::ClaimDeviceResponse>(nullptr);
}

inline void FinishClaimDeviceResponseBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::ClaimDeviceResponse> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedClaimDeviceResponseBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::ClaimDeviceResponse> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_CLAIMDEVICERESPONSE_TEO_H_