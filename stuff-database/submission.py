import os
from locust import HttpUser, task, between
import covidshield_pb2
import nacl
import base64
from nacl.public import PrivateKey, PublicKey, Box
import time
from google.protobuf.timestamp_pb2 import Timestamp


class User(HttpUser):
  wait_time = between(0,1)

  @task
  def submit_key(self):
    # Request a code
    headers = {'Authorization': 'Bearer ' + os.environ["KEY"]}
    r = self.client.post('/new-key-claim', headers=headers)
    code = r.text.strip('\n')

    # Claim the code
    key = PrivateKey.generate()
    app_public_key = key.public_key.encode(encoder=nacl.encoding.RawEncoder)
    app_private_key = key._private_key

    key_claim_request = covidshield_pb2.KeyClaimRequest()
    key_claim_response = covidshield_pb2.KeyClaimResponse()

    key_claim_request.one_time_code = code
    key_claim_request.app_public_key = app_public_key

    r = self.client.post('/claim-key', data=key_claim_request.SerializeToString())

    key_claim_response.ParseFromString(r.content)
    server_public_key = key_claim_response.server_public_key

    # Generate random keys
    keys = []

    for i in range(14):
      en_id = int((time.time() - (i * 86400)) / (60 * 10))
      tek = covidshield_pb2.TemporaryExposureKey()

      tek.key_data = nacl.utils.random(16)
      tek.transmission_risk_level = 4
      tek.rolling_start_interval_number = en_id
      tek.rolling_period = 144

      keys.append(tek)

    upload = covidshield_pb2.Upload()
    upload.timestamp.CopyFrom(Timestamp(seconds=int(time.time())))
    upload.keys.extend(keys)

    msg = upload.SerializeToString()

    box = Box(PrivateKey(app_private_key), PublicKey(server_public_key))
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    signed_payload = box.encrypt(msg, nonce=nonce)

    encypted_payload = covidshield_pb2.EncryptedUploadRequest()
    encypted_payload.server_public_key = server_public_key
    encypted_payload.app_public_key = app_public_key
    encypted_payload.nonce = nonce
    encypted_payload.payload = signed_payload.ciphertext

    self.client.post('/upload', data=encypted_payload.SerializeToString())