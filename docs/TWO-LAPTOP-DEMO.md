# Two-laptop LAN demo

Use two laptops on the same trusted private network. Both native clients need the same checkout revision and a successful `./scripts/setup.sh` run. The relay is untrusted, and LAN WebSockets expose routing metadata and public handshake fields to network observers. Keep the relay off public networks and disable port forwarding. Each browser connects only to the client on its own laptop.

1. On laptop 1, find its private IPv4 address. On macOS, open System Settings → Wi-Fi → Details → TCP/IP. Use the IPv4 address shown there. This example uses `192.168.1.20`.
2. In laptop 1’s repository, start the relay. Leave this terminal open.

   ```sh
   .venv/bin/python -m server.relay --lan --host 0.0.0.0 --port 8765 --observe-port 8766
   ```

3. Open a second terminal on laptop 1 and start Alice.

   ```sh
   .venv/bin/python -m client.app --name Alice --port 8001 \
     --data-dir .runtime/lan/Alice --contacts-dir .runtime/lan/contacts
   ```

4. On laptop 2, substitute laptop 1’s actual private IPv4 address and start Bob.

   ```sh
   .venv/bin/python -m client.app --name Bob --port 8002 --lan \
     --relay ws://192.168.1.20:8765 \
     --data-dir .runtime/lan/Bob --contacts-dir .runtime/lan/contacts
   ```

5. Open `http://127.0.0.1:8001/` on laptop 1 and `http://127.0.0.1:8002/` on laptop 2. In each conversation sidebar, open **Contact cards**. Export your own JSON card and transfer it to the other laptop. The QR option encodes the same public card. Use the JSON file if the camera cannot read the dense QR.
6. On each laptop, choose the other person’s file or paste its JSON, then select **Import unverified contact**. Open **Verify identity** and compare the full fingerprint aloud against the other person’s own displayed fingerprint. Pin it only when the fingerprints match.
7. Establish a secure session and send messages in both directions. Check each sender’s **Delivered** status after the recipient acknowledges the message. On laptop 1, open `http://127.0.0.1:8766/`. Send “hello” and look for a `message` row with a ciphertext preview. The page shows routing metadata and the preview, and refreshes every three seconds.
8. Stop each process with Ctrl-C in the terminal that started it.

If Bob cannot connect, confirm the IP, that both laptops are on the same network, and that the firewall permits the relay port from the private network. Some guest Wi-Fi networks block direct connections between devices. A relay restart clears its first-seen registration pins. Each client’s independently verified contact pin persists.
