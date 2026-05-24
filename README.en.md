[日本語](README.md)

# r2-copilot

`r2-copilot` is a Multi-Agent Collaboration Protocol (MCP) server for the powerful reverse engineering framework, [radare2](https://github.com/radare/radare2).

If you are looking to use radare2 llm tools:
* **r2mcp** - the [official radare2 mcp](https://github.com/radareorg/radare2-mcp)
* **r2ai** - the [official r2ai](https://github.com/radareorg/r2ai)

## Installation
🥳 r2-copilot has been added to r2pm! You can install with `r2pm -Uci r2-copilot` 

### self build
1.  Clone the repository
```bash
git clone https://github.com/your-repo/r2-copilot.git
cd r2-copilot
```

2.  Install dependencies
The project uses `uv` to manage dependencies.

```bash
uv sync
```

###  Install radare2
`r2pipe` requires `radare2` to be installed on your system for it to work correctly.

```bash
mkdir -p ~/.local/src/
cd ~/.local/src/
git clone https://github.com/radareorg/radare2 --depth 1
radare2/sys/install.sh
```

see. https://github.com/radareorg/radare2

## Usage

To start the server, run the following command:

```bash
./start.sh
```

This will launch the MCP server, which communicates via standard input/output (stdio).
The server waits for requests from a client, executes radare2 commands, and returns the results.

To use with gemini-cli, add the following to your `~/.gemini/settings.json`:

```json
{
  /*
      ...
  */
  "mcpServers": {
    /*
        ...
    */
    "r2-copilot": {
      "command": "/path/to/r2-copilot/start.sh"
      /* if you use uv:  
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/r2-copilot",
        "r2copilot"
      ]
      */
    }
  }
}
```

## Analysis Workflow

It is recommended to proceed with a typical binary analysis in the following steps.
Note that when using tools like gemini-cli, it is not necessary to memorize specific commands; natural language input is recommended.

1. Start a session

First, start a radare2 session for the file you want to analyze. This will issue a session ID that will be referenced in subsequent operations.

Command:
`create_session(file_path='<absolute_path_to_file>')`

Example:

 ### Analyzing /home/kali/ctf/iris/sqlate/vuln
 `print(default_api.create_session(file_path='/home/kali/ctf/iris/sqlate/vuln'))`
> Note: The session_id included in the response to this command is required for all subsequent commands.

2. Initial Static Analysis (Information Gathering)

Once the session has started, gather basic information about the binary. These commands can be executed in parallel.

 * Get basic binary information:
    `get_binary_info(session_id='<session_id>')`
    (Check architecture, bitness, file format, etc.)

 * Check security mechanisms:
    `check_security(session_id='<session_id>')`
    (Check if mitigation features like NX, PIE, Canary are enabled)

 * List strings:
    `get_strings(session_id='<session_id>')`
    (Extract embedded strings from the binary to find clues about the program's functionality and purpose)

 * List imported functions:
    `get_imports(session_id='<session_id>')`
    (Check which functions are being called from external libraries. The presence of dangerous functions like system or strcpy is an important indicator.)

3. Detailed Analysis

Next, run radare2's powerful auto-analysis feature. This will identify functions, basic blocks, and code cross-references.

Command:
`analyze_all(session_id='<session_id>')`

> Note: This process may take some time depending on the size of the binary.

4. Function Investigation

Once the auto-analysis is complete, list the identified functions to get an overall picture of the program.

 * Display a list of functions:
    `list_functions(session_id='<session_id>')`

 * Disassemble a specific function:
    `disassemble_function(session_id='<session_id>', address='<function_name_or_address>')`
    (For example, to examine the main function, which is the starting point of the program, specify address='sym.main')

5. Advanced Operations (Executing Raw Commands)

For more complex investigations or if a specific tool does not work as expected, you can use `execute_command` to directly execute any radare2 command.

Command:
`execute_command(session_id='<session_id>', command='<radare2_command>')`

 ```python
 # Search for functions whose names contain the string "login"
 print(default_api.execute_command(command='afl | grep login', session_id='...'))
 ```

## API Reference

The server exposes the following tools, each corresponding to a specific radare2 feature.

### Session Management

-   `create_session`: Starts a new radare2 session.
-   `list_sessions`: Lists active sessions.
-   `close_session`: Closes a session.
-   `switch_session`: Switches the current session.

### Analysis

-   `analyze_all`: Analyzes the entire binary (`aa`).
-   `analyze_function`: Analyzes the function at a specific address (`af`).
-   `list_functions`: Lists analyzed functions (`afl`).
-   `get_function_info`: Gets detailed information about a function (`afi`).
-   `get_xrefs_to`: Gets cross-references to a specific address (`axt`).
-   `get_xrefs_from`: Gets cross-references from a specific address (`axf`).

### Binary Information

-   `get_binary_info`: Gets comprehensive information about the binary (`iI`).
-   `get_sections`: Lists sections (`iS`).
-   `get_symbols`: Lists symbols (`is`).
-   `get_strings`: Lists strings (`iz`, `izz`).
-   `get_imports`: Lists imported functions (`ii`).
-   `get_entrypoint`: Gets the entry point (`ie`).
-   `check_security`: Checks for security features (NX, PIE, etc.).

### Disassembly

-   `disassemble`: Disassembles instructions (`pd`).
-   `disassemble_function`: Disassembles an entire function (`pdf`).
-   `print_hex`: Displays a hex dump (`px`).
-   `print_string`: Displays the string at an address (`psz`).

### Navigation

-   `seek`: Seeks to a specific address (`s`).
-   `seek_relative`: Seeks relative to the current position.
-   `get_current_address`: Gets the current address.
-   `set_block_size`: Sets the block size (`b`).

### Search

-   `search_bytes`: Searches for a byte pattern (`/x`).
-   `search_string`: Searches for a string (`/`).
-   `search_rop_gadgets`: Searches for ROP gadgets (`/R`).

### Writing

-   `write_hex`: Writes hexadecimal values (`wx`).
-   `write_assembly`: Writes assembly instructions (`wa`).
-   `write_nop`: Writes NOP instructions.

### Debugger

-   `continue_execution`: Continues program execution (`dc`).
-   `step_into`: Steps into an instruction (`ds`).
-   `step_over`: Steps over an instruction (`dso`).
-   `set_breakpoint`: Sets a breakpoint (`db`).
-   `list_breakpoints`: Lists breakpoints.
-   `get_registers`: Gets register values (`dr`).
-   `set_register`: Sets a register value.

### Flags

-   `list_flags`: Lists flags (labels) (`f`).
-   `create_flag`: Creates a flag.

### Configuration

-   `get_config`: Gets a configuration value (`e`).
-   `set_config`: Sets a configuration value.
-  `execute_command`: Executes a raw radare2 command.
