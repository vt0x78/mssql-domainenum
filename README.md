### MSSQL SID Brute-forcing Tool

This tool is designed to enumerate Active Directory (AD) objects by brute-forcing RIDs (Relative Identifiers) in a domain using MSSQL queries. It extracts the Domain SID and systematically queries for associated usernames or groups within a specified RID range.
Features

    Automatically extracts the Domain SID of the target MSSQL server.
    Performs RID brute-forcing starting from a user-specified RID.
    Stops dynamically after a defined number of consecutive failures.
    Customizable MSSQL connection parameters and brute-force options.
