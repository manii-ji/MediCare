from fastapi import FastAPI, Request, Form, Depends, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, String, select, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
import shutil
from typing import Optional

# ==========================================
# 1. SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "healthcare_secret_key_dev_2025"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8')[:72], hashed_password.encode('utf-8'))

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8')[:72], bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 2. DATABASE SETUP
# ==========================================
engine = create_engine("sqlite:///healthcare.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(100), unique=True)
    phone: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20), default="patient")  # patient | doctor

class Doctor(Base):
    __tablename__ = "doctors"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # linked User account
    name: Mapped[str] = mapped_column(String(100))
    specialization: Mapped[str] = mapped_column(String(100))
    experience: Mapped[str] = mapped_column(String(50))
    available_days: Mapped[str] = mapped_column(String(200))
    fee: Mapped[str] = mapped_column(String(30))
    image_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

class Appointment(Base):
    __tablename__ = "appointments"
    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(Integer)
    doctor_id: Mapped[int] = mapped_column(Integer)
    patient_name: Mapped[str] = mapped_column(String(100))
    doctor_name: Mapped[str] = mapped_column(String(100))
    specialization: Mapped[str] = mapped_column(String(100))
    date: Mapped[str] = mapped_column(String(30))
    time: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30), default="Pending")  # Pending | Confirmed | Rejected | Cancelled
    doctor_note: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="Frontend")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except jwt.InvalidTokenError:
        return None
    return db.scalars(select(User).where(User.email == email)).first()

def seed_data(db: Session):
    # Skip if already seeded
    if db.scalars(select(Doctor)).first():
        return

    doctor_data = [
        ("Dr. Priya Sharma",  "priya@medicare.com",  "Cardiologist",      "12 years", "Mon, Wed, Fri",            "₹800"),
        ("Dr. Rohit Mehta",   "rohit@medicare.com",  "Neurologist",       "8 years",  "Tue, Thu, Sat",            "₹1000"),
        ("Dr. Anita Desai",   "anita@medicare.com",  "Dermatologist",     "10 years", "Mon, Tue, Thu",            "₹600"),
        ("Dr. Suresh Patel",  "suresh@medicare.com", "Orthopedist",       "15 years", "Wed, Fri, Sat",            "₹900"),
        ("Dr. Kavita Rao",    "kavita@medicare.com", "Pediatrician",      "6 years",  "Mon, Wed, Fri",            "₹700"),
        ("Dr. Arjun Nair",    "arjun@medicare.com",  "General Physician", "5 years",  "Mon, Tue, Wed, Thu, Fri",  "₹400"),
    ]
    default_pw = get_password_hash("doctor123")

    for name, email, spec, exp, days, fee in doctor_data:
        # Create User account for doctor
        user = User(name=name, email=email, hashed_password=default_pw, role="doctor")
        db.add(user)
        db.flush()  # get user.id
        doctor = Doctor(user_id=user.id, name=name, specialization=spec,
                        experience=exp, available_days=days, fee=fee)
        db.add(doctor)

    db.commit()

with SessionLocal() as _db:
    seed_data(_db)

# ==========================================
# 4. AUTH ROUTES
# ==========================================

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html")

@app.post("/signup")
def signup_post(request: Request, name: str = Form(...), email: str = Form(...),
                phone: str = Form(default=""), password: str = Form(...), db: Session = Depends(get_db)):
    if db.scalars(select(User).where(User.email == email)).first():
        return templates.TemplateResponse(request=request, name="signup.html",
                                          context={"error": "Email already registered."})
    new_user = User(name=name, email=email, phone=phone, hashed_password=get_password_hash(password))
    db.add(new_user)
    db.commit()
    token = create_access_token(data={"sub": new_user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...),
               db: Session = Depends(get_db)):
    user = db.scalars(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request=request, name="login.html",
                                          context={"error": "Invalid email or password."})
    token = create_access_token(data={"sub": user.email})
    # Route to correct dashboard by role
    redirect_url = "/doctor/dashboard" if user.role == "doctor" else "/"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response

# ==========================================
# 5. PATIENT ROUTES
# ==========================================

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    if current_user.role == "doctor":
        return RedirectResponse(url="/doctor/dashboard", status_code=303)
    appointments = db.scalars(select(Appointment).where(Appointment.patient_id == current_user.id)).all()
    total     = len(appointments)
    confirmed = sum(1 for a in appointments if a.status == "Confirmed")
    pending   = sum(1 for a in appointments if a.status == "Pending")
    cancelled = sum(1 for a in appointments if a.status in ("Cancelled", "Rejected"))
    return templates.TemplateResponse(request=request, name="index.html", context={
        "current_user": current_user, "appointments": appointments,
        "total": total, "confirmed": confirmed, "pending": pending, "cancelled": cancelled
    })

@app.get("/doctors", response_class=HTMLResponse)
def doctors_page(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    doctors = db.scalars(select(Doctor)).all()
    return templates.TemplateResponse(request=request, name="doctors.html",
                                      context={"current_user": current_user, "doctors": doctors})

@app.get("/book/{doctor_id}", response_class=HTMLResponse)
def book_page(request: Request, doctor_id: int, current_user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    doctor = db.get(Doctor, doctor_id)
    return templates.TemplateResponse(request=request, name="book.html",
                                      context={"current_user": current_user, "doctor": doctor})

@app.post("/book/{doctor_id}")
def book_appointment(doctor_id: int, date: str = Form(...), time: str = Form(...), reason: str = Form(...),
                     db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    doctor = db.get(Doctor, doctor_id)
    appt = Appointment(
        patient_id=current_user.id, doctor_id=doctor_id,
        patient_name=current_user.name, doctor_name=doctor.name,
        specialization=doctor.specialization, date=date, time=time,
        reason=reason, status="Pending"
    )
    db.add(appt)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/cancel/{appointment_id}")
def cancel_appointment(appointment_id: int, current_user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    appt = db.get(Appointment, appointment_id)
    if appt and appt.patient_id == current_user.id and appt.status == "Pending":
        appt.status = "Cancelled"
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="profile.html",
                                      context={"current_user": current_user})

@app.post("/profile")
def update_profile(request: Request, name: str = Form(...), phone: str = Form(default=""),
                   db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    current_user.name = name
    current_user.phone = phone
    db.commit()
    return templates.TemplateResponse(request=request, name="profile.html",
                                      context={"current_user": current_user, "success": "Profile updated successfully."})

# ==========================================
# 6. DOCTOR ROUTES
# ==========================================

def get_doctor_profile(user: User, db: Session) -> Optional[Doctor]:
    return db.scalars(select(Doctor).where(Doctor.user_id == user.id)).first()

@app.get("/doctor/dashboard", response_class=HTMLResponse)
def doctor_dashboard(request: Request, current_user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    if not current_user or current_user.role != "doctor":
        return RedirectResponse(url="/login", status_code=303)
    doctor = get_doctor_profile(current_user, db)
    appointments = db.scalars(select(Appointment).where(Appointment.doctor_id == doctor.id)).all()
    total     = len(appointments)
    pending   = sum(1 for a in appointments if a.status == "Pending")
    confirmed = sum(1 for a in appointments if a.status == "Confirmed")
    rejected  = sum(1 for a in appointments if a.status == "Rejected")
    return templates.TemplateResponse(request=request, name="doctor_dashboard.html", context={
        "current_user": current_user, "doctor": doctor,
        "appointments": appointments,
        "total": total, "pending": pending, "confirmed": confirmed, "rejected": rejected
    })

@app.get("/doctor/appointment/{appt_id}", response_class=HTMLResponse)
def doctor_appt_detail(request: Request, appt_id: int, current_user: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    if not current_user or current_user.role != "doctor":
        return RedirectResponse(url="/login", status_code=303)
    doctor = get_doctor_profile(current_user, db)
    appt = db.get(Appointment, appt_id)
    if not appt or appt.doctor_id != doctor.id:
        return RedirectResponse(url="/doctor/dashboard", status_code=303)
    return templates.TemplateResponse(request=request, name="doctor_appt_detail.html",
                                      context={"current_user": current_user, "doctor": doctor, "appt": appt})

@app.post("/doctor/approve/{appt_id}")
def approve_appointment(appt_id: int, doctor_note: str = Form(default=""),
                        db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user or current_user.role != "doctor":
        return RedirectResponse(url="/login", status_code=303)
    doctor = get_doctor_profile(current_user, db)
    appt = db.get(Appointment, appt_id)
    if appt and appt.doctor_id == doctor.id and appt.status == "Pending":
        appt.status = "Confirmed"
        appt.doctor_note = doctor_note or "Your appointment has been confirmed."
        db.commit()
    return RedirectResponse(url="/doctor/dashboard", status_code=303)

@app.post("/doctor/reject/{appt_id}")
def reject_appointment(appt_id: int, doctor_note: str = Form(default=""),
                       db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user or current_user.role != "doctor":
        return RedirectResponse(url="/login", status_code=303)
    doctor = get_doctor_profile(current_user, db)
    appt = db.get(Appointment, appt_id)
    if appt and appt.doctor_id == doctor.id and appt.status == "Pending":
        appt.status = "Rejected"
        appt.doctor_note = doctor_note or "Appointment could not be accommodated."
        db.commit()
    return RedirectResponse(url="/doctor/dashboard", status_code=303)
