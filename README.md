# ScentStation

> A multi-brand management platform for automated perfume sampling machines

**Java Programming** course project — Ho Chi Minh City University of Transport (UTH)

🌐 [Phiên bản tiếng Việt](README.md)

---

## 1. Introduction

ScentStation is a web application that enables multiple perfume brands to operate a shared network of sampling machines placed in shopping centres.

Customers choose a fragrance on the machine's screen, pay by QR code, and the machine dispenses a small sample. Each brand signs in to the platform and sees only its own data: machines, bottle inventory, revenue and sales statistics.

The project does not use physical hardware. The machine is replaced by a simulator that communicates with the server over the MQTT protocol.

## 2. Key Features

| Feature | Description |
|---|---|
| Authentication and authorisation | Three roles: Administrator, Brand Manager, Staff |
| Brand management | Create, update and delete brands and fragrance catalogues |
| Machine management | Track machines, slots and operating status |
| Ordering and payment | Customers select a fragrance and pay via simulated QR |
| Machine control | Send dispense commands and receive results |
| Inventory management | Track bottle stock with low-stock alerts |
| Statistics and reports | Revenue dashboard, best-selling fragrances, CSV export |
| Incident handling | Record failed orders and refund requests |

## 3. System Architecture

```
┌──────────────┐    REST API    ┌──────────────┐     MQTT     ┌──────────────┐
│   Frontend   │ ─────────────> │   Backend    │ ───────────> │   Machine    │
│   Next.js    │ <───────────── │ Spring Boot  │ <─────────── │ (simulated)  │
└──────────────┘                └──────┬───────┘              └──────────────┘
                                       │
                                ┌──────┴───────┐
                                │  PostgreSQL  │
                                └──────────────┘
```

- **Frontend**: customer-facing screens and the admin dashboard
- **Backend**: business logic, REST API, sending commands to machines
- **PostgreSQL**: data storage
- **Machine (simulated)**: receives dispense commands and reports results over MQTT

## 4. Technology Stack

| Component | Technology |
|---|---|
| Backend | Java 21, Spring Boot 3, Spring Security, Spring Data JPA |
| Frontend | Next.js, React, TypeScript, Tailwind CSS |
| Database | PostgreSQL 16 |
| Device communication | MQTT (Eclipse Mosquitto, Eclipse Paho) |
| Security | JWT, BCrypt, HMAC-SHA256 |
| Tools | IntelliJ IDEA, VS Code, Git, GitHub, Jira, Docker |

## 5. Repository Structure

```
LapTrinhJava/
├── backend/        Spring Boot source code
├── frontend/       Next.js source code
├── Report/         Project report (chapters)
├── Work Log/       Weekly work logs
└── README.md
```

## 6. Getting Started

### Prerequisites

- JDK 21
- Node.js 20 or later
- Docker Desktop
- Git

### Steps

**Step 1 — Clone the repository**

```bash
git clone https://github.com/tkimngan040/LapTrinhJava.git
cd LapTrinhJava
```

**Step 2 — Start PostgreSQL and MQTT**

```bash
docker run -d --name scent-db -p 5432:5432 \
  -e POSTGRES_DB=scentstation \
  -e POSTGRES_USER=scent \
  -e POSTGRES_PASSWORD=scent \
  postgres:16

docker run -d --name scent-mqtt -p 1883:1883 \
  eclipse-mosquitto:2.0 mosquitto -c /mosquitto-no-auth.conf
```

**Step 3 — Run the backend**

```bash
cd backend
./mvnw spring-boot:run
```

The backend runs at `http://localhost:8080`

**Step 4 — Run the frontend** (in a new terminal)

```bash
cd frontend
npm install
npm run dev
```

The frontend runs at `http://localhost:3000`

## 7. Team Members

| No. | Full name | Role |
|---|---|---|
| 1 | Tran Thi Kim Ngan | Team leader |
| 2 | Nguyen Duy Long | Member |
| 3 | Pham Tran Tra My | Member |
| 4 | Kim Tuyen | Member |
| 5 | Nguyen Hoai Anh | Member |

## 8. Working Conventions

| Item | Where | Link |
|---|---|---|
| Task assignment | Jira | [ScentStation on Jira](https://ut-team-i1h68a6n.atlassian.net/jira/software/projects/SCENT/summary) |
| Report files (Word) | Google Drive | [ScentStation folder](https://drive.google.com/drive/folders/1dQa6OVoUEMZda-g5p1xXC_eeKa2F2zlt?usp=sharing) |
| Source code | GitHub | [LapTrinhJava](https://github.com/tkimngan040/LapTrinhJava) |

### Workflow

1. Pick up a task in **Jira** and move it to **In Progress**
2. Upload finished report files (Word) to **Google Drive**
3. For source code, create a branch on **GitHub** named after the Jira key, e.g. `docs/SCENT-5-technologies`
4. Open a **Pull Request**; the team leader reviews it before merging into `main`
5. Move the Jira task to **Done**

---

*This project is for educational purposes.*
