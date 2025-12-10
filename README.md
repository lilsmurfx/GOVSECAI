🚨 GovSecAI — National Security Intelligence Assistant

Streamlit UI + FastAPI Backend + RAG Engine + Admin Dashboard + Render Deployment

GovSecAI is an AI-powered intelligence & governance platform designed to support government agencies with:

Threat detection summaries

Policy analysis & document intelligence

Citizen service automation (GovChat)

Secure RAG search over government documents

Analyst dashboard with metrics & logs

Multi-role interface (Analyst / Admin / Public Portal)

This repository contains the complete implementation including:

📦 📂 Repository Structure
GovsecAI/
│
├── streamlit_app/             # Streamlit multipage frontend
│   ├── pages/
│   ├── components/
│   ├── styles/
│   └── app.py
│
├── backend/                   # FastAPI backend
│   ├── main.py                # Main API entrypoint
│   ├── rag_engine.py          # RAG pipeline
│   ├── faiss_builder.py       # Builds FAISS index
│   ├── security.py            # Simple API key + auth
│   └── db.py                  # SQLite persistence
│
├── data/
│   ├── sample_docs.json       # Example gov documents
│   ├── govsec_index.faiss     # Embeddings store
│   └── prompts/               # System prompts
│
├── utils/
│   ├── pdf_export.py
│   ├── text_cleaner.py
│   └── logger.py
│
├── requirements.txt
├── Procfile                   # Render deployment
├── README.md
└── .gitignore

⚙️ Features
🛡️ Government Intelligence Tools

Policy analysis assistant

Threat report generator

Secure document summarizer

RAG-powered search across government files

CBC-style structured reports

🎛️ Streamlit Multipage App

Analyst Dashboard

Document Upload Center

GovChat (Public Portal Simulation)

Admin Metrics & Logs

🚀 FastAPI Backend

RAG search endpoint

Threat analysis API

Secure admin endpoints

Feedback + logs storage using SQLite

📁 FAISS Vector Search

Custom embeddings for gov datasets

Optimized retrieval tuned for policy/legal documents

📝 PDF Export

Threat reports

Chat transcripts

Policy briefs

🌐 Deployment-Ready for Render.com

No Docker needed

Procfile included

Automatic build & deploy

🧪 Running the Project Locally
1. Create virtual environment
python -m venv venv

2. Activate environment

Windows

venv\Scripts\activate


Mac/Linux

source venv/bin/activate

3. Install dependencies
pip install -r requirements.txt

🔍 Build the FAISS Index
python backend/faiss_builder.py --data data/sample_docs.json --index data/govsec_index.faiss

🚦 Start the Backend (FastAPI)
uvicorn backend.main:app --reload --port 8000


API will run at:
http://localhost:8000/docs

🖥️ Run the Streamlit Frontend
streamlit run streamlit_app/app.py


Frontend runs at:
http://localhost:8501

🌍 Deploying to Render

This repo already includes:

✔ Procfile
✔ requirements.txt
✔ startup command for Streamlit + FastAPI
✔ render.yaml (optional if needed)

Basic Deploy Steps:

Push this repo to GitHub

Open https://dashboard.render.com

Create new Web Service

Connect this repo

Set Start Command:

uvicorn backend.main:app --host 0.0.0.0 --port 8000


Or for Streamlit:

streamlit run streamlit_app/app.py --server.port 10000 --server.address 0.0.0.0

🛂 API Authentication (Optional)

If API_KEY is set in environment variables:

export GOVSEC_API_KEY="yourkey"


Then each request must include:

x-api-key: yourkey

📊 Admin Dashboard Metrics

The system tracks:

Document views

RAG query volume

Response quality feedback

Threat classification logs

Exported reports count

User roles & activity

Stored automatically in SQLite (govsec.db).

🔒 Security Notes

GovSecAI follows basic security hygiene:

API key support

Sanitized inputs

Restricted admin endpoints

SQLite persistence (swap to Postgres for production)

No citizen personal data included by default

📝 To-Do / Roadmap

 Multi-tenant support

 End-to-end encryption

 Postgres migration

 Government digital ID integration

 Role-based authorization

 Offline local-network deployment





