import os
import cbor2
from src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2 import SeedDotSeigr, FileMetadata

class SerializationManager:
    def save(self, seigr_file, base_dir, use_cbor=False):
        filename = f"{seigr_file.creator_id}_{seigr_file.index}.seigr.{'cbor' if use_cbor else 'pb'}"
        file_path = os.path.join(base_dir, filename)

        os.makedirs(base_dir, exist_ok=True)
        with open(file_path, 'wb') as f:
            f.write(self.serialize(seigr_file, use_cbor))

        return file_path

    def serialize(self, seigr_file, use_cbor=False):
        if use_cbor:
            return cbor2.dumps(seigr_file.metadata_manager.get_metadata())
        else:
            seigr_file_proto = SeedDotSeigr()
            file_metadata = FileMetadata(**seigr_file.metadata_manager.get_metadata())
            seigr_file_proto.file_metadata.CopyFrom(file_metadata)
            return seigr_file_proto.SerializeToString()
