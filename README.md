# SOC Sim Setup (Simple)

This project works in **two Docker steps**:

1. Start **Wazuh single-node**.
2. Start the **SOC simulator services** (`log_generator`, `traffic_generator`, `dashboard`).

Everything shares one Docker network called `soc-shared`.

## What runs where

- `wazuh-docker/single-node`: Wazuh manager, Wazuh indexer, Wazuh dashboard
- project root `docker-compose.yml`: log generators + custom analyst dashboard

The generators write JSON logs into `./data/raw_logs`, and the Wazuh manager reads those same files from inside its container as `/soc_logs`.

## Before you start

- Install Docker Desktop
- Make sure Docker Compose is available: `docker compose version`
- Create the log folder if it does not exist:

```bash
mkdir -p data/raw_logs
```

If you are on Linux, set:

```bash
sudo sysctl -w vm.max_map_count=262144
```

You can skip that command on macOS Docker Desktop.

## Step 1: Start Wazuh in single-node mode

Move into the Wazuh single-node folder:

```bash
cd /Users/moeezcheema/Desktop/soc-sim-llm-main/wazuh-docker/single-node
```

Generate the certificates once:

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

Start Wazuh:

```bash
docker compose up -d
```

Wait about 1 to 2 minutes for Wazuh Indexer and Dashboard to finish starting.

### Wazuh URLs

- Wazuh dashboard: [https://localhost](https://localhost)
- Custom SOC dashboard will be started in Step 2 at [http://localhost:8080](http://localhost:8080)

## Step 2: Start the simulator services

Open another terminal and go back to the project root:

```bash
cd /Users/moeezcheema/Desktop/soc-sim-llm-main
```

Build and start the project services:

```bash
docker compose up --build -d
```

This starts:

- `log_generator`: writes baseline process logs
- `traffic_generator`: writes web traffic logs
- `dashboard`: reads alerts from Wazuh indexer

## Step 3: Open the dashboards

- Custom SOC dashboard: [http://localhost:8080](http://localhost:8080)
- Wazuh dashboard: [https://localhost](https://localhost)

## Simple restart commands

From `wazuh-docker/single-node`:

```bash
docker compose down
docker compose up -d
```

From the project root:

```bash
docker compose down
docker compose up --build -d
```

## If alerts do not appear

Check these in order:

1. Wazuh containers are up:

```bash
cd /Users/moeezcheema/Desktop/soc-sim-llm-main/wazuh-docker/single-node
docker compose ps
```

2. Project containers are up:

```bash
cd /Users/moeezcheema/Desktop/soc-sim-llm-main
docker compose ps
```

3. Log files exist:

```bash
ls -lah /Users/moeezcheema/Desktop/soc-sim-llm-main/data/raw_logs
```

You should see files like:

- `system_logs.jsonl`
- `web_logs.jsonl`

## The important idea

Keep it simple:

- Start Wazuh from `wazuh-docker/single-node`
- Start the simulator from the project root
- Both use the same Docker network: `soc-shared`
- Logs are shared through `data/raw_logs`
