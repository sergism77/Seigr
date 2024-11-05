# dot_seigr

**dot_seigr** is a decentralized data encoding, segmentation, and storage solution built on the **Seigr Protocol** within the **Seigr Urcelial-net**. This protocol-driven framework offers secure, adaptive data management designed for scalability and resilience, inspired by mycelial networks. Through advanced **HyphaCrypt** cryptographic methods, **senary encoding**, **layered hashing**, and **adaptive replication**, dot_seigr achieves secure and traceable data storage across decentralized nodes with IPFS compatibility.

---

## Purpose

dot_seigr enables secure and modular data management within the Seigr Urcelial-net, supporting decentralized storage, traceable access, and adaptive replication for dynamic environments. With the Seigr Protocol, dot_seigr provides self-healing mechanisms, multidimensional data links, and flexible scaling, ideal for environments with fluctuating node availability and resource constraints.

---

## Key Components and Technical Details

### Seigr Protocol

The **Seigr Protocol** underpins dot_seigr’s architecture, providing standardized data structures, cryptographic standards, and encoding methods. Key elements of the protocol include:
- **Senary Encoding**: Base-6 encoding for efficient data representation and storage reduction.
- **Layered Hashing**: Hierarchical hash trees with dynamic salts to secure data and prevent tampering.
- **Multidimensional Links**: Primary and secondary links for flexible, multi-path retrieval.
- **Temporal Layering**: Historical snapshots that support rollback to previous secure states.

### .seigr Files and Seed Clusters

**.seigr files** are the basic storage units, defined by the Seigr Protocol, each precisely sized at **53194 KB** to optimize distribution across nodes. Each `.seigr` file includes:
- **Header**: Metadata fields (e.g., file type, creator ID, Seigr Protocol version, and replication metrics).
- **Senary Encoded Data**: Data in base-6 encoding to enhance storage efficiency and obfuscation.
- **Hash and Link Management**: Multi-layered hash trees generated through **HyphaCrypt** to secure data and facilitate retrieval.
- **Temporal Layers**: Stores historical snapshots for secure rollback capabilities.

These files are designed to be adaptive, with reserved blank spaces for minor updates, allowing modification without full file regeneration.

### SeigrEncoder and SeigrDecoder

The **SeigrEncoder** and **SeigrDecoder** modules are core to the encoding and decoding processes in dot_seigr, aligning closely with the Seigr Protocol.

#### SeigrEncoder

The **SeigrEncoder** is responsible for segmenting and encoding raw data into `.seigr` files, using senary encoding and cryptographic hashing:

- **Data Segmentation**: Splits data into chunks based on `TARGET_BINARY_SEGMENT_SIZE`, allowing uniform segment sizes.
- **Senary Encoding**: Encodes each segment in base-6 format, reducing file size and adding obfuscation.
- **Cluster Management**: Utilizes the **SeigrClusterManager** to organize segments into clusters and manage multidimensional links.
- **Multidimensional Link Management**: Creates primary and secondary hash links via **LinkManager** for multidimensional retrieval paths.
- **Adaptive Replication**: Adjusts replication counts based on network demands, integrating with the Immune System to ensure data security and availability.
  
Each encoded segment is saved as a `.seigr` file with associated metadata, and clusters are saved with hierarchical references, aligning with Seigr Protocol standards.

#### SeigrDecoder

The **SeigrDecoder** reconstructs original files by retrieving and verifying `.seigr` segments:

- **Data Retrieval**: Collects segments from distributed nodes based on primary and secondary links.
- **Integrity Verification**: Uses hierarchical hash verification to ensure data integrity and authenticity.
- **Senary Decoding**: Converts base-6 encoded data back to binary for accurate reassembly.
- **Temporal Recovery**: Supports rollback by retrieving historical snapshots stored in temporal layers for secure recovery.

The SeigrDecoder ensures that all segments meet Seigr Protocol requirements for data integrity, providing reliable and secure data reconstruction.

### SeedDotSeigr: Seed Files for Cluster Organization

Seed files manage groups of `.seigr` files, forming logical clusters. Each **SeedDotSeigr** file includes:
- **Root Hash**: Serves as the foundation for the cluster’s hash hierarchy.
- **Cluster Management**: Initiates new clusters as the current cluster reaches capacity, maintaining organized references and replication levels.
- **Segment Hash Indexing**: Indexes `.seigr` file hashes for multidimensional retrieval paths.
- **Self-Healing and Adaptive Replication**: Monitors access and integrity to adjust replication based on demand and integrity status.

### HyphaCrypt Module

The **HyphaCrypt** module implements Seigr Protocol-compliant cryptographic methods, providing:
- **Senary Encoding**: Encodes data in base-6 for space efficiency and obfuscation.
- **Layered Hashing with Dynamic Salts**: Uses SHA-256 and SHA-512 hashing with entropy-based dynamic salts for robust security.
- **Hierarchical Hash Trees**: Enables multidimensional retrieval paths with layered hash trees.
- **Linkage and Temporal Layers**: Generates primary and secondary links, storing historical layers for secure rollback.

---

## Security and Scalability

dot_seigr’s decentralized structure, guided by the Seigr Protocol, provides scalable, secure, and resilient data handling across the Seigr Urcelial-net. Key features include:
- **Tamper Detection**: Layered hashing and dynamic salts prevent unauthorized modifications.
- **Adaptive Replication**: Adjusts replication based on network demand, ensuring availability while balancing load.
- **Self-Healing and Rollback**: Restores compromised segments through the Immune System, supported by temporal snapshots and the **6RR Mechanism**.
- **Scalability**: Modular seed and cluster management allows for continuous network expansion without disrupting existing data.

The Seigr Protocol enables dot_seigr to offer a decentralized, resilient, and secure storage solution that meets the evolving demands of Seigr Urcelial-net, ensuring traceability and accessibility across a decentralized environment.
