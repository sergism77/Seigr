# dot_seigr

**dot_seigr** is a decentralized data encoding, segmentation, and storage solution built on the Seigr Urcelial-net, a resilient network inspired by mycelial structures. Designed for scalability, adaptability, and security, dot_seigr leverages senary encoding, layered hashing, and adaptive replication to support dynamic, secure data storage across decentralized nodes.

The dot_seigr ecosystem integrates advanced **HyphaCrypt** cryptographic methods, **multidimensional linkage**, and **temporal layering** to ensure data integrity, traceability, and adaptive replication within an IPFS-compatible framework.

---

## Purpose

dot_seigr is a core component of Seigr Urcelial-net, enabling decentralized and secure handling of segmented data while supporting both accessibility and traceability across distributed environments. Unlike traditional centralized storage, dot_seigr utilizes multidimensional data links and self-healing mechanisms, optimized for environments where nodes may intermittently go offline or have varying resource constraints.

---

## Key Components and Technical Details

### .seigr Files and Seed Clusters

**.seigr files** are the foundational storage units within dot_seigr, each sized precisely at **304 KB** to optimize storage distribution. Each file contains:
- **Header**: Metadata fields include file type, creator ID, versioning, hierarchical hash trees, and dynamic replication counts.
- **Senary Encoded Data**: Data encoded in base-6 format, reducing storage demands while enhancing security and obfuscation.
- **Integrity and Link Hashing**: Generated via **HyphaCrypt** with multi-layered hash trees for resilience against tampering and providing multidimensional retrieval pathways.
- **Temporal Layers**: Historical snapshots enable rollback to previous secure states, allowing adaptive data recovery and versioning.

These files adapt to network demand, with blank spaces reserved for minor updates, allowing data modification without full file regeneration, an advantage in mutable environments.

### SeedDotSeigr: Seed Files for Cluster Management

**Seed files** serve as entry points, managing groups of `.seigr` files into logical clusters. Each seed file tracks:
- **Root Hash**: Identifies the initial .seigr file associated with the cluster, forming the foundation of the cluster hierarchy.
- **Cluster Management**: Dynamically creates new clusters as file counts increase, with each seed managing references and replication demands to ensure efficient retrieval.
- **Linked Segment Hashes**: Indexes hashes of associated `.seigr` files, supporting multidimensional linkage that allows efficient and flexible data access across nodes.
- **Self-Healing and Adaptive Replication**: Actively monitors access and integrity to adjust replication counts based on threat detection and usage demands, as part of the **Immune System**.

Each seed file initiates new clusters when capacity is reached, providing modular growth across the Seigr Urcelial-net.

### HyphaCrypt Module

The **HyphaCrypt** module is the cryptographic backbone of dot_seigr, delivering:
- **Senary Encoding**: Compresses data into base-6, enhancing compatibility and minimizing storage costs.
- **Multilayered Hashing with Dynamic Salts**: Combines SHA-256 and SHA-512 hashing with entropy-derived dynamic salts to secure data.
- **Hierarchical Hash Trees**: Supports multidimensional retrieval by creating layered hash trees up to configurable depths.
- **Xorshift-Based PRNG**: Generates secure random numbers for salting and transformations, ensuring cryptographic randomness.
- **Secure Linkage and Temporal Layers**: Generates links that support multi-path retrievals and stores historical layers for rollback.

### Immune System and Adaptive Replication

The **Immune System** continuously monitors data integrity and triggers **adaptive replication** based on threat levels and access frequency. Key functions include:
1. **Integrity Pings**: Periodic checks to validate segment integrity using multidimensional hashes.
2. **Threat Detection and Adaptive Replication**: Replicates high-demand data more broadly and initiates **self-healing** if integrity issues arise.
3. **Temporal Rollback**: Automatically restores data from previous layers in response to security threats, preserving the latest verified state.
4. **6RR Mechanism**: Randomized security replication across sixth-layer hashes in multidimensional paths, ensuring resilience in cases of widespread attack.

### dot_seigr and Seed Management Classes

The **dot_seigr** and **SeedDotSeigr** classes manage data compression, encoding, segmentation, storage, and retrieval across distributed nodes.

#### dot_seigr.py
1. **Data Compression and Senary Encoding**: Compresses data and encodes it using senary, employing a substitution-permutation network (SPN) for enhanced obfuscation.
2. **Hierarchical Hashing**: Implements HyphaCrypt hashing and dynamic salting to prevent tampering.
3. **Temporal Layering**: Supports versioning by storing historical states for secure, multi-layered rollback.
4. **Multidimensional Links**: Stores primary and secondary hash links for resilient and flexible retrieval paths.
5. **Adaptive Replication**: Utilizes access patterns to adjust replication dynamically, ensuring efficiency and availability.

#### SeedDotSeigr.py
1. **Cluster Management**: Dynamically initiates new clusters as existing ones reach capacity, facilitating modular network scaling.
2. **Multidimensional Cross-Referencing**: Tracks segment hashes and inter-cluster references, supporting efficient retrieval across spatial and temporal layers.
3. **6RR Security**: Implements randomized replication of sixth-layer hashes to maintain robust security, aiding in recovery and self-healing.

### SeigrEncoder and SeigrDecoder

**SeigrEncoder** and **SeigrDecoder** are entry points for encoding and decoding data.

#### SeigrEncoder
- **Compression and Encoding**: Compresses and senary encodes data, segmenting it into `.seigr` files.
- **Seed Management**: Initializes and manages seed clusters for organized file storage.
- **Adaptive Blank Space and Clustering**: Ensures space for minor updates and manages clustering when limits are reached.

#### SeigrDecoder
- **Data Retrieval and Integrity Verification**: Retrieves segments, verifying hashes before reassembly.
- **Temporal Data Handling**: Uses historical layer data for secure rollback and data reconstruction.

---

## Security and Scalability

dot_seigr’s decentralized architecture is designed to support large-scale, secure data handling across Seigr Urcelial-net. Key mechanisms include:
- **Tamper Detection**: Uses multi-layered hashing and dynamic salts to detect any unauthorized changes.
- **Adaptive and Demand-Based Replication**: Increases replication based on network demand and usage, balancing load and availability.
- **Self-Healing and Rollback**: Restores compromised segments using temporal snapshots and replication, aided by the **6RR Mechanism**.
- **Scalability**: Modular seed and cluster management allows continuous growth, supporting new data without disrupting existing structure.

dot_seigr offers a decentralized, self-sustaining storage and data management solution that evolves with user demand, leveraging a resilient cryptographic foundation and IPFS-compatible architecture to ensure secure, traceable, and scalable data distribution across the Seigr Urcelial-net.