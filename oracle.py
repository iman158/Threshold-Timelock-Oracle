import os
import time
import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass
from hashlib import sha256
from functools import partial
import asyncio
from aiohttp import ClientSession

# Cryptographic primitives
from bls import PyBLS
from vdf import VDF, pietrzak_verify
from dkg import DKGProtocol

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ThresholdTimelockOracle")

@dataclass(frozen=True)
class ParticipantConfig:
    id: str
    address: str
    public_key: bytes

@dataclass(frozen=True)
class OracleConfig:
    threshold: int
    participants: List[ParticipantConfig]
    vdf_difficulty: int = 1000000
    network_timeout: int = 30

class ThresholdTimelockOracle:
    def __init__(self, config: OracleConfig, node_id: str):
        self.config = config
        self.node_id = node_id
        self.bls = PyBLS()
        self.vdf = VDF()
        self.dkg = DKGProtocol()

        # Initialize node state
        self.public_key: Optional[bytes] = None
        self.private_share: Optional[bytes] = None
        self.nonce_commitments: List[bytes] = []

    async def initialize(self) -> None:
        """Run DKG protocol to establish threshold keys"""
        logger.info("Initializing threshold scheme using DKG")
        self.public_key, self.private_share = await self.dkg.run_protocol(
            participants=self.config.participants,
            threshold=self.config.threshold,
            node_id=self.node_id
        )

    async def compute_vdf(self, input_data: bytes, difficulty: int) -> Tuple[bytes, bytes]:
        """Compute verifiable delay function with given difficulty"""
        logger.debug(f"Starting VDF computation (difficulty: {difficulty})")
        start_time = time.time()
        output, proof = self.vdf.compute(input_data, difficulty)
        elapsed = time.time() - start_time
        logger.info(f"VDF completed in {elapsed:.2f}s")
        return output, proof

    async def threshold_sign(self, message: bytes) -> bytes:
        """Collect threshold signatures from participants"""
        logger.info(f"Initiating threshold signing for message: {message.hex()[:16]}...")

        # Get own signature share
        own_share = self.bls.sign(self.private_share, message)
        shares = [(self.node_id, own_share)]

        # Request signatures from other participants
        async with ClientSession(timeout=self.config.network_timeout) as session:
            tasks = [
                self._request_signature_share(session, p, message)
                for p in self.config.participants if p.id != self.node_id
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.warning(f"Signature request failed: {str(result)}")
                    continue
                shares.append(result)

        if len(shares) < self.config.threshold:
            raise ValueError("Insufficient signature shares collected")

        # Verify and combine signatures
        return self._combine_shares(message, shares)

    async def _request_signature_share(self, session: ClientSession,
                                       participant: ParticipantConfig,
                                       message: bytes) -> Tuple[str, bytes]:
        """Request signature share from a network participant"""
        url = f"{participant.address}/sign"
        data = {
            "message": message.hex(),
            "nonce_commitments": [c.hex() for c in self.nonce_commitments]
        }

        async with session.post(url, json=data) as response:
            if response.status != 200:
                raise ValueError(f"Invalid response from {participant.id}")

            response_data = await response.json()
            return (participant.id, bytes.fromhex(response_data['signature']))

    def _combine_shares(self, message: bytes, shares: List[Tuple[str, bytes]]) -> bytes:
        """Combine and verify threshold signature shares"""
        # Verify individual signatures
        valid_shares = []
        for participant_id, sig in shares:
            pubkey = next(p.public_key for p in self.config.participants if p.id == participant_id)
            if self.bls.verify(pubkey, message, sig):
                valid_shares.append(sig)
            else:
                logger.warning(f"Invalid signature from {participant_id}")

        if len(valid_shares) < self.config.threshold:
            raise ValueError("Insufficient valid signatures")

        # Combine valid shares
        return self.bls.aggregate(valid_shares)

    async def generate_timelock_output(self, message: bytes) -> Tuple[bytes, bytes]:
        """
        Full timelock oracle workflow:
          1. Compute the VDF output and proof using a partially applied function.
          2. Verify the VDF proof using a lambda for a functional check.
          3. Use the VDF output as the input for threshold signing.
        """
        # Compute VDF with difficulty pre-set
        compute_vdf_with_difficulty = partial(self.compute_vdf, difficulty=self.config.vdf_difficulty)
        vdf_output, proof = await compute_vdf_with_difficulty(message)

        # Verify the VDF proof using functional programming (lambda function)
        verify_vdf = lambda res: res if pietrzak_verify(message, res[0], res[1], self.config.vdf_difficulty) else None
        verified = verify_vdf((vdf_output, proof))
        if verified is None:
            raise ValueError("VDF proof verification failed")

        # Use the VDF output as the message to collect a threshold signature
        signature = await self.threshold_sign(vdf_output)

        return vdf_output, signature

# Example Usage:
async def main():
    config = OracleConfig(
        threshold=3,
        participants=[
            ParticipantConfig("node1", "http://localhost:8001", b"pubkey1"),
            ParticipantConfig("node2", "http://localhost:8002", b"pubkey2"),
            ParticipantConfig("node3", "http://localhost:8003", b"pubkey3"),
        ],
        vdf_difficulty=1000000,
    )
    oracle = ThresholdTimelockOracle(config, "node1")
    await oracle.initialize()
    message = b"Test Message"
    output, signature = await oracle.generate_timelock_output(message)
    print("VDF Output:", output.hex())
    print("Threshold Signature:", signature.hex())

if __name__ == "__main__":
    asyncio.run(main())
