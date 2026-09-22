# 🚀 MailTrace-AI: Teammate Quickstart Guide

Yeh guide un sabhi teammates ke liye hai jo MailTrace-AI ko apne laptop par pehli baar setup aur run kar rahe hain.

---

## 📋 Prerequisites (Pehle Yeh Check Karein)
1. **Python 3.10 ya 3.11** installed hona chahiye (Installation ke time *"Add Python to PATH"* check karein).
2. **Node.js (LTS version 18 ya 20)** installed hona chahiye.
3. **Git** installed hona chahiye.

---

## 🛠️ Step 1: Repositories Clone Karein
Ek naya folder banayein (jaise `MailTrace-AI` ya `Project`) aur terminal mein run karein:

```bash
# 1. Backend clone karein
git clone https://github.com/rajatgarg112/MailTrace-Backend.git

# 2. Frontend clone karein
git clone https://github.com/rajatgarg112/MailTrace-Frontend.git
```

> **Note**: Folder structure aisa dikhega:
> ```text
> 📁 MailTrace-AI/
> ├── 📁 MailTrace-Backend/  (ya backend/)
> └── 📁 MailTrace-Frontend/ (ya frontend/)
> ```

---

## 📦 Step 2: Dependencies Install Karein (One Time Only)

### Backend Dependencies:
Terminal mein Backend folder open karein:
```bash
cd MailTrace-Backend
pip install -r requirements.txt
```

### Frontend Dependencies:
Terminal mein Frontend folder open karein:
```bash
cd ../MailTrace-Frontend
npm install
```

---

## ⚡ Step 3: Run Karein (1-Click Multi-Service Auto Launcher)

Aapko bas **`start_all.bat`** file par double click karna hai!
Yeh file chahe aap parent folder mein rakhein ya `MailTrace-Backend` ke andar se run karein, yeh **automatically**:
- Backend aur Frontend folders ko dhoondh legi.
- FastAPI Backend ko Port `8000` par start karegi.
- Fono User Webmail ko Port `5173` par start karegi.
- Security SOC Gateway ko Port `5174` par start karegi.
- Aapke browser mein teeno dashboards automatically open kar degi!

### Port URLs:
- 📬 **User Webmail (Fono)**: `http://localhost:5173`
- 🛡️ **SOC Security Gateway**: `http://localhost:5174`
- ⚙️ **FastAPI Backend Docs**: `http://localhost:8000/docs`

---

## 🛑 Step 4: Servers Stop Karna
Jab kaam ho jaye, toh bas **`stop_all.bat`** par double click karein. Yeh sabhi running servers ko safely band kar dega.
