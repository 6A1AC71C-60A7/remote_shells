# Index
- [I Abstract](#abstract)
- [II Implementation](#implementation)
- [III Usage](#usage)
- [IV Notes](#notes)

## <a name=abstract> Abstract </a>
TODO: paragraph format
- 2 deamons: TLS and Shell
- Open port (starting at 6047 which increments until find one)
- A server is created

## <a name=implementation> Implementation </a>
TODO: paragraph format
- None library had been used (no linker)
- CLIENT <-> TLSd <-> SHELLd
- Accepts only 1 client at the same time

## <a name=usage> Usage </a>
TODO: paragraph format
- Launch
- Comunicate
- Exit deamon by typing: "exit"

## <a name=notes> Notes </a>
TODO: paragraph format
- Shell isn't interactive yet
- Could inf loop if none port is avalaible
- Rebember to clear locks for testing
