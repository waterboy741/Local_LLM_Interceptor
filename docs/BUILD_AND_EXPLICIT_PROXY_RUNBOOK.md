# Build and run llm_interceptor on macOS

Run the Mac commands from the repository root. This runbook covers the explicit HTTP proxy tested with OpenCode on Ubuntu and Ollama on a separate lab device. Start the application as your regular macOS user.

## 1. Build and test

The project requires macOS Command Line Tools, CMake 3.24 or later, Ninja, and Qt 6.11 or later. If the Command Line Tools are missing, install them first.

```sh
xcode-select --install
```

If you use Homebrew and are missing the build dependencies, install them and point CMake at the Qt modules. This follows the repository's CI configuration.

```sh
brew install cmake ninja qtbase qthttpserver
export CMAKE_PREFIX_PATH="$(brew --prefix qtbase):$(brew --prefix qthttpserver):$(brew --prefix qtwebsockets)${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
```

Configure, build, and test Release.

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release --output-on-failure
```

Use the Debug preset if you are developing or diagnosing the app.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
```

## 2. Run the application

Launch the Release app from the terminal to see its output.

```sh
./build/release/llm_interceptor.app/Contents/MacOS/llm_interceptor
```

For Debug, use the corresponding binary.

```sh
./build/debug/llm_interceptor.app/Contents/MacOS/llm_interceptor
```

## 3. Run the OpenCode lab test through the explicit proxy

Start Ollama and check that its version endpoint responds from the Mac. Substitute the current Ollama address if it has changed.

```sh
curl --noproxy '*' --fail --silent --show-error --max-time 5 \
  'http://192.168.1.141:11434/api/version'
```

In llm_interceptor, open **Configuration**. These are the settings from the verified lab run.

| Field | Value |
| --- | --- |
| Mac interface | `en0` |
| Client IPv4 | `192.168.1.169`, the Ubuntu machine running OpenCode |
| LLM IPv4 | `192.168.1.141`, the Ollama server |
| LLM TCP port | `11434` |
| Proxy listen port | `11434` if available, or `0` for **Automatic** |
| API paths | `/v1/chat/completions` |

Click **Prepare configuration**, then **Start Observe proxy**. Copy the URL after **Proxy listening at**. On Ubuntu, check that the displayed listener reaches Ollama. Replace the example URL with the one shown by the app if the address or port differs.

```sh
proxy_url='http://192.168.1.16:11434'
curl --noproxy '*' --fail --silent --show-error --max-time 5 \
  "$proxy_url/api/version"
```

Save OpenCode's existing Ollama base URL. Set it to the proxy URL followed by `/v1`. In the example above, use `http://192.168.1.16:11434/v1`. Send a synthetic prompt such as `Reply with LAB_OK`. Confirm that OpenCode receives a reply and that **Requests** shows the matching `POST /v1/chat/completions`.

To test a manual edit, select **Modify** under **Modify settings**, enable **Hold matching requests for manual editing**, leave **Automatic operation** at **None**, and click **Apply mode and rules**. Send a new synthetic prompt. Select the held request, edit the last user message, and click **Apply last message to editable JSON**, then **Validate and forward edit**. Select the request in **Requests** and look below **Messages** for the change and the `manual: edited` audit entry. The **Full JSON** panel displays the original request.

## 4. Restore direct access

Restore the saved Ollama base URL in OpenCode. Click **Clear session** in llm_interceptor. On Ubuntu, confirm the direct version endpoint works again and send one test prompt in OpenCode.

```sh
curl --noproxy '*' --fail --silent --show-error --max-time 5 \
  'http://192.168.1.141:11434/api/version'
```

The explicit proxy uses the URL configured in OpenCode and requires no helper, ARP table changes, or PF rules. For a one-device test with a mock upstream, use the [single Mac demo](EXPLICIT_PROXY_DEMO.md).
