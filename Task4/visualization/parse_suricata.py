import json

with open("eve.json") as f:
    for line in f:
        event = json.loads(line)
        if event.get("event_type") == "alert":
            print(f"[ALERT] {event['alert']['signature']} from {event.get('src_ip')} to {event.get('dest_ip')}")
