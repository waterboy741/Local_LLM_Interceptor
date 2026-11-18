# Single Mac explicit proxy demo

Use this walkthrough to show request inspection, manual editing, and streaming with a synthetic upstream. You need the built app and Python 3. The client, proxy, and mock server all run on the Mac's loopback interface.

1. From the repository root, run `python3 scripts/mock_ollama_demo.py`. Keep it open and note the port it prints.
2. In the app's Configuration tab, select the loopback interface (`lo0` on macOS). Enter `127.0.0.1` for **Client IPv4** and **LLM IPv4**. Set **LLM TCP port** to the printed mock port, **API paths** to `/v1/chat/completions`, and **Proxy listen port** to **Automatic**. Click **Prepare configuration** and **Start Observe proxy**.
3. In another terminal, set `proxy_url` to the listener URL shown by the app and run the command below. Keep that terminal visible so you can see each event arrive.

```sh
proxy_url='http://127.0.0.1:PROXY_PORT'
curl --noproxy '*' --no-buffer --fail --max-time 120 \
  -H 'Content-Type: application/json' \
  --data '{"model":"demo","stream":true,"messages":[{"role":"user","content":"Original demo message"}]}' \
  "$proxy_url/v1/chat/completions"
```

In Observe mode, the Requests tab shows the original JSON and its messages. The terminal streams two events containing `Mock received: ` and `Original demo message`, followed by `[DONE]`.

To demonstrate manual editing, open **Modify settings**, select **Modify**, check **Hold matching requests for manual editing**, leave **Automatic operation** at **None**, and click **Apply mode and rules**. Run the same curl command again. In **Held requests**, select the request and replace the final message with the following JSON.

```json
{"role":"user","content":"Edited in the proxy"}
```

Click **Apply last message to editable JSON**, then **Validate and forward edit** before the hold expires. The terminal should stream `Edited in the proxy` instead of the original text. In **Requests**, open the request to show its original and edited JSON. Click **Clear session** and press Ctrl+C in the mock server terminal when finished.
