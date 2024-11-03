# dot_seigr

**dot_seigr** is a decentralized data encoding, segmentation, and storage solution built on the Seigr Urcelial-net. Inspired by natural mycelial networks, it is designed for scalability, adaptability, and security, leveraging unique encoding techniques and cryptographic hashing. 

The system combines **senary encoding**, **modular data segmentation**, and **secure hashing** to create a resilient, distributed framework for managing data across multiple nodes in a network, where each node has varying storage and processing capabilities.

## Purpose

As a core component of Seigr Urcelial-net, dot_seigr aims to handle sensitive, segmented data securely, ensuring both accessibility and traceability across distributed systems. Unlike traditional data storage, which relies on centralized databases, dot_seigr employs a decentralized, IPFS-compatible format that offers flexibility and reliability in environments where devices may go offline or experience limited network bandwidth.

---

## Key Components and Technical Details

### .seigr Files and Seed Clusters

**.seigr files** are the fundamental unit of storage within dot_seigr, each sized precisely at 539 KB, with reserved header space. Each file contains:
- **Header**: Includes metadata such as file type, creator ID, versioning, hash chaining, and replication count. It also lists associated segments, enabling cross-referencing for data retrieval.
- **Senary Encoded Data**: Each file’s data, compressed and encoded using senary (base-6) format, optimized for storage and transmission efficiency.
- **Integrity Hash**: Generated with SHA-256 hashing and dynamic salting using the HyphaCrypt module, this hash ensures tamper-proofing and guarantees data integrity.

These files are created with adaptive blank space to allow minor updates without regenerating the entire structure, making them suitable for environments where data mutability may be necessary over time.

### SeedDotSeigr: Seed Files for Cluster Management

**Seed files** act as the primary reference points for collections of `.seigr` files, grouping them into clusters. Each seed file tracks:
- **Root Hash**: Identifies the initial .seigr file that the seed manages, serving as a foundation for retrieval.
- **Associated Files**: List of hashes for `.seigr` files within the cluster, aiding in efficient data access.
- **Cluster Management**: As data grows, the seed file dynamically initiates new clusters and maintains a list of cluster hashes, preventing any one seed file from reaching its size limit.

Each seed cluster can store references to `.seigr` files up to a specified limit, after which it automatically creates a new cluster, allowing for continuous growth and adaptability.

### HyphaCrypt Module

The **HyphaCrypt** module is central to the security and data integrity of dot_seigr, offering:
- **Senary Encoding/Decoding**: Converts binary data into senary (base-6) format, reducing storage demands and enhancing compatibility across different node capacities.
- **SHA-256 Hashing with Dynamic Salting**: Protects data integrity with dynamic salts derived from UUIDs, timestamps, and secure random numbers. This ensures each hash remains unique and guards against unauthorized tampering.
- **Xorshift-based PRNG**: Provides cryptographically secure random numbers for salting and various transformations within the encoding and hashing processes, adding unpredictability to the system.

### dot_seigr and Seed Management

The **dot_seigr** and **SeedDotSeigr** classes handle data compression, encoding, segmentation, and storage within the network.

#### dot_seigr.py
1. **Data Compression**: Compresses raw data before encoding, reducing file size and preserving bandwidth across distributed nodes.
2. **Senary Encoding**: Encodes compressed data in senary format, making it compact and secure. Each byte is transformed using a substitution-permutation network (SPN) to increase obfuscation.
3. **Hash Generation and Verification**: Applies SHA-256 hashing with unique salts to maintain data integrity and track each file’s lineage within the network.
4. **Adaptive Replication and Associated Segments**: Ensures that high-demand data is replicated more widely, balancing the network load.

#### SeedDotSeigr.py
1. **Cluster Management**: Manages groups of `.seigr` files, creating new clusters when current limits are reached to avoid overwhelming any one file.
2. **Segment Tracking**: Tracks associated segment hashes within each seed file, ensuring efficient retrieval and reassembly for large data sets.
3. **Cross-Referencing**: Each cluster points to its `.seigr` files and any additional clusters, allowing distributed nodes to locate and assemble data efficiently.

### SeigrEncoder and SeigrDecoder

**SeigrEncoder** and **SeigrDecoder** are the entry points for encoding and decoding data within dot_seigr.

#### SeigrEncoder
- **Compression and Encoding**: Compresses and encodes data to senary format.
- **Segmentation**: Divides encoded data into fixed-size `.seigr` files, each with reserved blank space to allow for future updates.
- **Seed File Management**: Initializes seed files, adding references to `.seigr` files as they are created. When seed clusters reach their size limit, the encoder generates new clusters.

#### SeigrDecoder
- **Seed File Loading**: Loads all seed files and retrieves hashes for each `.seigr` file in a cluster.
- **Segment Verification**: Retrieves and verifies each `.seigr` file by its hash, ensuring data integrity before reassembly.
- **Data Reassembly**: Decodes senary-encoded segments, decompresses them, and reconstructs the original data in byte format.

---

## Security and Scalability

dot_seigr is designed to support large-scale distributed networks where data security and integrity are paramount. Key mechanisms include:
- **Tamper Detection**: SHA-256 hashing and dynamic salts prevent unauthorized data modifications, ensuring each `.seigr` file remains unchanged once stored.
- **Demand-Based Replication**: Uses the replication count to manage storage and retrieval efficiency, scaling `.seigr` copies according to network demand.
- **Adaptability for Data Growth**: Seed clusters and reserved blank space allow for both vertical and horizontal scalability, accommodating evolving data sets over time.
