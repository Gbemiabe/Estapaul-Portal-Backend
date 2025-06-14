// server.js - Complete Version
const express = require('express');
const dotenv = require('dotenv');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// PDF Generation Libraries
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');

// Explicitly get the default export from node-fetch, which is the fetch function itself.
const nodeFetch = require('node-fetch');
const _fetchApi = nodeFetch.default || nodeFetch; 

const Headers = nodeFetch.Headers || (nodeFetch.default && nodeFetch.default.Headers);
const Request = nodeFetch.Request || (nodeFetch.default && nodeFetch.default.Request);
const Response = nodeFetch.Response || (nodeFetch.default && nodeFetch.default.Response);

// Config
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001; 

// Initialize Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY, {
    global: {
        fetch: _fetchApi,
        Headers: Headers,
        Request: Request,
        Response: Response,
    }
});

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Define the precise order of classes for promotion and general use
const CLASS_ORDER = [
  'Creche', 'KG 1', 'KG 2', 'Nursery 1', 'Nursery 2', 'Primary 1',
  'Primary 2', 'Primary 3', 'Primary 4', 'Primary 5', 'JSS 1',
  'JSS 2', 'JSS 3', 'SS1', 'SS2', 'SS3'
];

const ALL_CLASSES = [...CLASS_ORDER];

// Dynamically create the PROMOTION_MAP based on CLASS_ORDER
const PROMOTION_MAP = {};
for (let i = 0; i < CLASS_ORDER.length - 1; i++) {
    PROMOTION_MAP[CLASS_ORDER[i]] = CLASS_ORDER[i + 1];
}
PROMOTION_MAP[CLASS_ORDER[CLASS_ORDER.length - 1]] = 'GRADUATED';

console.log("PROMOTION_MAP:", PROMOTION_MAP);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS 
app.use((req, res, next) => {
    const allowedOrigins = [
        'http://localhost:3000',
        'http://localhost:3001',
        'https://estapaulschool.onrender.com' 
    ];
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// File Upload Setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage });

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        console.log('Authentication: No token provided');
        return res.sendStatus(401);
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log('Authentication: Token verification failed', err.message);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// Middleware to authorize teacher role
const authorizeTeacher = (req, res, next) => {
    if (req.user && req.user.role === 'teacher') {
        next(); // User is a teacher, proceed to the next middleware/route handler
    } else {
        res.status(403).json({ message: 'Access denied: Not a teacher' });
    }
};

// Helpers
const hashPassword = async (password) => await bcrypt.hash(password, 10);

// This function is generally not needed for 'users' table registration
// as 'session' column has a default TEXT value.
async function getCurrentSessionId() {
    const { data, error } = await supabase
        .from('sessions')
        .select('id')
        .eq('is_current', true)
        .single();
    if (error || !data) throw new Error('No active session');
    return data.id;
}

// Verify Bucket on Startup
(async () => {
    try {
        const { error } = await supabase.storage.getBucket('school-media');
        if (error) throw error;
        console.log('✅ Verified: school-media bucket exists');
    } catch (err) {
        console.error('❌ Bucket error:', err.message);
        process.exit(1);
    }
})();

// ======================
// ROUTES
// ======================

// [1] STUDENT REGISTRATION
app.post('/api/auth/register/student', upload.single('picture'), async (req, res) => {
    try {
        const { student_id, password, full_name, gender, class: student_class } = req.body;
        const pictureFile = req.file;

        // Validation
        if (!student_id || !password || !full_name || !gender || !student_class || !pictureFile) {
            if (pictureFile) fs.unlinkSync(pictureFile.path);
            return res.status(400).json({ message: 'All fields required' });
        }

        // Check duplicate
        const { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('student_id', student_id)
            .single();

        if (existing) {
            fs.unlinkSync(pictureFile.path);
            return res.status(409).json({ message: 'Student ID exists' });
        }

        // Upload to school-media
        const fileExt = path.extname(pictureFile.originalname);
        const fileName = `students/${student_id}-${Date.now()}${fileExt}`;
        const { data: uploadData, error: uploadError } = await supabase.storage
            .from('school-media')
            .upload(fileName, fs.readFileSync(pictureFile.path), {
                contentType: pictureFile.mimetype,
                upsert: false
            });

        fs.unlinkSync(pictureFile.path);
        if (uploadError) throw uploadError;

        // Create user
        const { data: user, error: userError } = await supabase
            .from('users')
            .insert([{
                role: 'student',
                student_id,
                password: await hashPassword(password),
                full_name,
                gender,
                class: student_class,
                is_active: true,
                profile_picture: `${process.env.SUPABASE_URL}/storage/v1/object/public/school-media/${fileName}`
            }])
            .select()
            .single();

        if (userError) {
            await supabase.storage.from('school-media').remove([fileName]);
            throw userError;
        }

        // Generate token
        const token = jwt.sign({ id: user.id, role: 'student' }, JWT_SECRET, { expiresIn: '8h' });
        res.status(201).json({
            message: 'Registration successful',
            token,
            user: {
                id: user.id,
                student_id: user.student_id,
                full_name: user.full_name,
                role: 'student'
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// [2] TEACHER REGISTRATION
app.post('/api/auth/register/teacher', async (req, res) => {
    try {
        const { email, password, full_name, gender, class: teacher_class } = req.body;
        if (!email || !password || !full_name || !gender || !teacher_class) {
            return res.status(400).json({ message: 'All fields required' });
        }

        // Check duplicate
        const { data: existing } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existing) return res.status(409).json({ message: 'Email exists' });

        // Create teacher
        const { data: user, error } = await supabase
            .from('users')
            .insert([{
                role: 'teacher',
                email,
                password: await hashPassword(password),
                full_name,
                gender,
                class: teacher_class,
                is_active: true
            }])
            .select()
            .single();

        if (error) throw error;

        const token = jwt.sign({ id: user.id, role: 'teacher' }, JWT_SECRET, { expiresIn: '8h' });
        res.status(201).json({
            message: 'Teacher registered',
            token,
            user: {
                id: user.id,
                email: user.email,
                full_name: user.full_name,
                role: 'teacher'
            }
        });

    } catch (error) {
        console.error('Teacher error:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// [3] LOGIN (ALL ROLES)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password, role } = req.body;
        if (!identifier || !password || !role) {
            return res.status(400).json({ message: 'All fields required' });
        }

        // Determine identifier field
        const identifierField = role === 'student' ? 'student_id' : 'email';

        // Fetch user
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq(identifierField, identifier)
            .eq('role', role)
            .single();

        // Check if user exists and password is correct
        if (error || !user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign({ id: user.id, role }, JWT_SECRET, { expiresIn: '8h' });
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                identifier,
                full_name: user.full_name,
                role,
                class: user.class
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// [4] SCHOOL INFO
app.get('/api/school-info', async (req, res) => {
    try {
        // Get the public URL of the logo from Supabase storage
        const { data: { publicUrl: logoUrl } = {} } = await supabase.storage
            .from('school-media')
            .getPublicUrl('logo.png');

        res.json({
            name: 'ESTAPAUL GROUP OF SCHOOLS',
            motto: 'Readers are Leaders',
            established: 2010,
            address: 'Behind Women Development Center, Igede Ekiti',
            phone: '+2348131819188',
            email: 'info@estapaulschools.com',
            logo_url: logoUrl || 'https://placehold.co/150x50/cccccc/000000?text=Logo+Missing', // Fallback
            description: 'Quality education from Creche to Senior Secondary',
            principal_name: 'Mr Olusegun',
            proprietor_name: 'Mr Adetunkasi Adewale',
            social_media: {
                facebook: 'https://facebook.com/estapaulschools',
                twitter: 'https://twitter.com/estapaulschools',
                instagram: 'https://instagram.com/estapaulschools'
            },
            school_hours: {
                weekdays: '7:30am - 3:00pm',
                weekends: 'Closed'
            }
        });
    } catch (error) {
        console.error('School info error:', error);
        res.status(500).json({ 
            message: 'Server error',
            error: error.message 
        });
    }
});

// [5] GET ALL SESSIONS
app.get('/api/sessions', authenticateToken, async (req, res) => {
    try {
        const { data: sessions, error } = await supabase
            .from('sessions')
            .select('id, name')
            .order('name', { ascending: false }); // Order by name for consistency

        if (error) throw error;
        res.json({ sessions });
    } catch (error) {
        console.error('Error fetching sessions:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// ======================
// TEACHER ENDPOINTS
// ======================

// [8] GET TEACHER'S CLASS STUDENTS
app.get('/api/teacher/students', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Unauthorized - Teachers only' });

        const { data: teacher, error: teacherError } = await supabase
            .from('users')
            .select('id, class, full_name, email')
            .eq('id', req.user.id)
            .single();
        if (teacherError || !teacher) return res.status(404).json({ message: 'Teacher record not found' });
        if (!teacher.class) return res.status(400).json({ message: 'Teacher has no class assigned' });

        const { data: students, error: studentsError } = await supabase
            .from('users')
            .select('id, student_id, full_name, gender, profile_picture, is_active')
            .eq('role', 'student')
            .eq('class', teacher.class)
            .order('full_name', { ascending: true });
        if (studentsError) return res.status(500).json({ message: 'Database error fetching students' });

        res.json({ class: teacher.class, students: students || [] });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// [9] ADD SUBJECT TO CLASS
app.post('/api/teacher/subjects', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Unauthorized - Teachers only' });
        const { subject_name } = req.body;
        if (!subject_name) return res.status(400).json({ message: 'Subject name required' });

        const { data: teacher, error: teacherError } = await supabase
            .from('users')
            .select('class')
            .eq('id', req.user.id)
            .single();
        if (teacherError || !teacher) throw new Error('Teacher not found');

        const { data: subject, error: subjectError } = await supabase
            .from('subjects')
            .insert([{ name: subject_name, class: teacher.class, teacher_id: req.user.id }])
            .select()
            .single();
        if (subjectError) throw subjectError;

        res.status(201).json({ message: 'Subject added successfully', subject });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// [10] GET CLASS SUBJECTS
app.get('/api/teacher/subjects', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Unauthorized - Teachers only' });

        const { data: teacher, error: teacherError } = await supabase
            .from('users')
            .select('class')
            .eq('id', req.user.id)
            .single();
        if (teacherError || !teacher) throw new Error('Teacher not found');

        const { data: subjects, error: subjectsError } = await supabase
            .from('subjects')
            .select('id, name, created_at')
            .eq('class', teacher.class)
            .order('name', { ascending: true });
        if (subjectsError) throw subjectsError;

        res.json({ class: teacher.class, subjects: subjects || [] });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// [11] UPLOAD STUDENT RESULTS - FIXED VERSION
app.post('/api/teacher/results', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Unauthorized - Teachers only' });

        const {
            student_id,
            term,
            session,
            subject_id, 
            pt1,
            pt2,
            pt3,
            exam,
            attendance,
            punctuality,
            neatness,
            honesty,
            responsibility,
            creativity,
            sports
        } = req.body;

        if (!student_id || !term || !session || !subject_id || pt1 == null || pt2 == null || 
            pt3 == null || exam == null || attendance == null || punctuality == null || 
            neatness == null || honesty == null || responsibility == null || 
            creativity == null || sports == null) {
            return res.status(400).json({ message: 'All fields required' });
        }

        const { data: student, error: studentError } = await supabase
            .from('users')
            .select('id, class')
            .eq('student_id', student_id)
            .single();
        if (studentError || !student) throw new Error('Student not found');

        const { data: teacher, error: teacherError } = await supabase
            .from('users')
            .select('class')
            .eq('id', req.user.id)
            .single();
        if (teacherError || !teacher) throw new Error('Teacher not found');
        if (teacher.class !== student.class) {
            return res.status(403).json({ message: 'Unauthorized - You can only upload results for your class' });
        }

        const { data: subject, error: subjectError } = await supabase
            .from('subjects')
            .select('id, name')
            .eq('id', subject_id)
            .eq('class', teacher.class)
            .single();
        if (subjectError || !subject) {
            return res.status(400).json({ message: 'Invalid subject or subject not found for this class' });
        }

        const avgPT = Math.round((parseInt(pt1) + parseInt(pt2) + parseInt(pt3)) / 3);
        const totalScore = avgPT + parseInt(exam);
        let grade, remark;
        if (totalScore >= 70) { grade = 'A'; remark = 'Excellent'; }
        else if (totalScore >= 60) { grade = 'B'; remark = 'Very Good'; }
        else if (totalScore >= 50) { grade = 'C'; remark = 'Credit'; }
        else if (totalScore >= 40) { grade = 'D'; remark = 'Fair'; }
        else if (totalScore >= 30) { grade = 'E'; remark = 'Poor'; }
        else { grade = 'F'; remark = 'Very Poor'; }

        let sessionId;
        const { data: existingSession } = await supabase
            .from('sessions')
            .select('id')
            .eq('name', session)
            .single();
        if (existingSession) {
            sessionId = existingSession.id;
        } else {
            const { data: newSession } = await supabase
                .from('sessions')
                .insert([{ name: session }])
                .select('id')
                .single();
            sessionId = newSession.id;
        }

        const { data: result, error: resultError } = await supabase
            .from('results')
            .upsert([{
                student_id: student.id,
                subject_id: subject_id,
                term,
                session_id: sessionId,
                pt1,
                pt2,
                pt3,
                avg_pt: avgPT,
                exam,
                total_score: totalScore,
                grade,
                remark,
                teacher_id: req.user.id,
                is_approved: false
            }], {
                onConflict: 'student_id,subject_id,term,session_id'
            })
            .select()
            .single();
        if (resultError) throw resultError;

        const { error: skillsError } = await supabase
            .from('psychomotor')
            .upsert([{
                student_id: student.id,
                term,
                session_id: sessionId,
                attendance,
                punctuality,
                neatness,
                honesty,
                responsibility,
                creativity,
                sports,
                created_by: req.user.id
            }], {
                onConflict: 'student_id,term,session_id'
            });
        if (skillsError) throw skillsError;

        res.status(201).json({
            message: 'Results uploaded successfully',
            result: {
                ...result,
                subject_name: subject.name
            }
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// GET single student result for a subject+term+sessi
// GET single student psychomotor for a term/session (for pre-filling upload form)
app.get('/api/teacher/psychomotor/:studentId/:term/:session', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Unauthorized - Teachers only' });

        const { studentId, term, session } = req.params;

        const { data: student, error: studentError } = await supabase
            .from('users')
            .select('id, class')
            .eq('student_id', studentId)
            .single();
        if (studentError || !student) return res.status(404).json({ message: 'Student not found' });

        const { data: teacher, error: teacherError } = await supabase
            .from('users')
            .select('class')
            .eq('id', req.user.id)
            .single();
        if (teacherError || !teacher) return res.status(404).json({ message: 'Teacher not found' });
        if (teacher.class !== student.class) {
            return res.status(403).json({ message: 'Unauthorized - You can only view results for your class' });
        }

        const { data: sessionData, error: sessionError } = await supabase
            .from('sessions')
            .select('id')
            .eq('name', session)
            .single();
        if (sessionError || !sessionData) {
            return res.status(404).json({ message: 'Session not found' });
        }
        const sessionId = sessionData.id;

        const { data: psychomotor, error: psychomotorError } = await supabase
            .from('psychomotor')
            .select('attendance, punctuality, neatness, honesty, responsibility, creativity, sports')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session_id', sessionId)
            .single();

        if (psychomotorError && psychomotorError.code !== 'PGRST116') throw psychomotorError;

        res.json({ psychomotor: psychomotor || null });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// [12] GET STUDENT RESULTS FOR TEACHER 

app.get('/api/teacher/student-results/:studentId/:term/:session', authenticateToken, async (req, res) => {
    try {
        // 🔧 FIX: Decode URL parameters first
        const studentId = decodeURIComponent(req.params.studentId);
        const term = decodeURIComponent(req.params.term);
        const session = decodeURIComponent(req.params.session);

        console.log('🔍 URL Parameters Debug:', {
            raw: req.params,
            decoded: { studentId, term, session }
        });

        // 1. Find student in users table
        const { data: student, error: studentError } = await supabase
            .from('users')
            .select('id, full_name, class, student_id')
            .eq('student_id', studentId)
            .eq('role', 'student')
            .single();

        if (studentError || !student) {
            console.error('Student lookup failed:', { 
                studentError, 
                searchedStudentId: studentId
            });
            return res.status(404).json({ message: 'Student not found' });
        }

        console.log('✅ Student found:', student);

        // 2. Verify teacher access
        const { data: teacher, error: teacherError } = await supabase
            .from('users')
            .select('class')
            .eq('id', req.user.id)
            .eq('role', 'teacher')
            .single();

        if (teacherError || !teacher) {
            return res.status(403).json({ message: 'Teacher not authorized' });
        }

        if (teacher.class !== student.class) {
            return res.status(403).json({ 
                message: 'You can only view results for your own class' 
            });
        }

        console.log('✅ Teacher access verified');

        // 🔧 FIX: Changed 'academic_results' to 'results' and simplified the query
        const { data: academicResults, error: academicError } = await supabase
            .from('results') // ← Changed table name
            .select(`
                id, subject_id, pt1, pt2, pt3, exam, total_score, grade, remark
            `) // ← Removed subjects join for now
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session', session);

        if (academicError) {
            console.error('Academic results fetch error:', academicError);
            throw academicError;
        }

        console.log('✅ Academic results fetched:', academicResults?.length || 0, 'records');

        // Get subject names separately if needed
        const subjectIds = academicResults ? academicResults.map(ar => ar.subject_id) : [];
        let subjectNames = {};
        
        if (subjectIds.length > 0) {
            const { data: subjects, error: subjectsError } = await supabase
                .from('subjects')
                .select('id, name')
                .in('id', subjectIds);
            
            if (!subjectsError && subjects) {
                subjects.forEach(subject => {
                    subjectNames[subject.id] = subject.name;
                });
            } else {
                console.warn('Could not fetch subject names:', subjectsError);
            }
        }

        let formattedAcademicResults = [];
        let currentTermOverallTotal = 0;
        let currentTermOverallObtainable = 0;

        // Process current term academic results
        if (academicResults && academicResults.length > 0) {
            formattedAcademicResults = academicResults.map(ar => {
                const total = ar.total_score;
                const remark = ar.remark;
                const grade = ar.grade;
                const avg_pt = (ar.pt1 + ar.pt2 + ar.pt3) / 3;

                currentTermOverallTotal += total;
                currentTermOverallObtainable += 100;

                return {
                    id: ar.id,
                    subject_id: ar.subject_id,
                    subject_name: subjectNames[ar.subject_id] || 'Unknown Subject', // ← Using separate lookup
                    pt1: ar.pt1,
                    pt2: ar.pt2,
                    pt3: ar.pt3,
                    avg_pt: avg_pt,
                    exam: ar.exam,
                    total_score: total,
                    grade: grade,
                    remark: remark
                };
            });
        }

        // --- Cumulative Calculations ---
        let firstTermOverallTotalScore = 0;
        let secondTermOverallTotalScore = 0;
        let cumulativeOverallTotal = currentTermOverallTotal;
        let cumulativeOverallObtainable = currentTermOverallObtainable;

        let prevTerm1SubjectScores = {};
        let prevTerm2SubjectScores = {};

        if (term === '2nd' || term === '3rd') {
            // 🔧 FIX: Changed table name here too
            const { data: firstTermAcademicResults, error: firstTermAcademicError } = await supabase
                .from('results') // ← Changed table name
                .select('total_score, subject_id')
                .eq('student_id', student.id)
                .eq('term', '1st')
                .eq('session', session);

            if (firstTermAcademicError) console.error("Error fetching 1st term academic results:", firstTermAcademicError);

            if (firstTermAcademicResults && firstTermAcademicResults.length > 0) {
                firstTermOverallTotalScore = firstTermAcademicResults.reduce((sum, res) => {
                    prevTerm1SubjectScores[res.subject_id] = res.total_score;
                    return sum + res.total_score;
                }, 0);
                cumulativeOverallTotal += firstTermOverallTotalScore;
                cumulativeOverallObtainable += firstTermAcademicResults.length * 100;
            }
        }

        if (term === '3rd') {
            // 🔧 FIX: Changed table name here too
            const { data: secondTermAcademicResults, error: secondTermAcademicError } = await supabase
                .from('results') // ← Changed table name
                .select('total_score, subject_id')
                .eq('student_id', student.id)
                .eq('term', '2nd')
                .eq('session', session);

            if (secondTermAcademicError) console.error("Error fetching 2nd term academic results:", secondTermAcademicError);

            if (secondTermAcademicResults && secondTermAcademicResults.length > 0) {
                secondTermOverallTotalScore = secondTermAcademicResults.reduce((sum, res) => {
                    prevTerm2SubjectScores[res.subject_id] = res.total_score;
                    return sum + res.total_score;
                }, 0);
                cumulativeOverallTotal += secondTermOverallTotalScore;
                cumulativeOverallObtainable += secondTermAcademicResults.length * 100;
            }
        }

        // Enhance formattedAcademicResults with previous term scores
        formattedAcademicResults = formattedAcademicResults.map(ar => {
            let enhancedResult = { ...ar };

            if (term === '2nd' || term === '3rd') {
                enhancedResult.first_term_total_score = prevTerm1SubjectScores[ar.subject_id] !== undefined ? prevTerm1SubjectScores[ar.subject_id] : null;
            } else {
                enhancedResult.first_term_total_score = null;
            }

            if (term === '3rd') {
                enhancedResult.second_term_total_score = prevTerm2SubjectScores[ar.subject_id] !== undefined ? prevTerm2SubjectScores[ar.subject_id] : null;
            } else {
                enhancedResult.second_term_total_score = null;
            }

            // Calculate subject-specific cumulative average
            let subjectScoresForCumAvg = [ar.total_score];
            if (enhancedResult.first_term_total_score !== null) {
                subjectScoresForCumAvg.push(enhancedResult.first_term_total_score);
            }
            if (enhancedResult.second_term_total_score !== null) {
                subjectScoresForCumAvg.push(enhancedResult.second_term_total_score);
            }
            enhancedResult.subject_cum_avg = subjectScoresForCumAvg.length > 0
                ? (subjectScoresForCumAvg.reduce((a, b) => a + b, 0) / subjectScoresForCumAvg.length).toFixed(2)
                : null;

            return enhancedResult;
        });

        // Fetch psychomotor results
        const { data: psychomotorData, error: psychomotorError } = await supabase
            .from('psychomotor_skills')
            .select('*')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session', session)
            .single();

        if (psychomotorError && psychomotorError.code !== 'PGRST116') {
            console.error('Error fetching psychomotor skills:', psychomotorError);
        }

        // Fetch attendance
        const { data: attendanceData, error: attendanceError } = await supabase
            .from('attendance')
            .select('days_opened, days_present')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session', session)
            .single();

        if (attendanceError && attendanceError.code !== 'PGRST116') {
            console.error('Error fetching attendance:', attendanceError);
        }

        // Calculate overall cumulative average
        let overallCumulativeAvg = null;
        if (cumulativeOverallObtainable > 0) {
            overallCumulativeAvg = ((cumulativeOverallTotal / cumulativeOverallObtainable) * 100).toFixed(2);
        }

        let position = 'N/A';

        console.log('✅ Sending successful response');

        res.status(200).json({
            student: student,
            term: term,
            session: session,
            academicResults: formattedAcademicResults,
            psychomotor: psychomotorData || {},
            attendance: attendanceData || {},
            overallPerformance: {
                totalScored: currentTermOverallTotal,
                totalObtainable: currentTermOverallObtainable,
                percentage: currentTermOverallObtainable > 0 ? ((currentTermOverallTotal / currentTermOverallObtainable) * 100).toFixed(2) : '0.00',
                firstTermTotalScore: term === '2nd' || term === '3rd' ? firstTermOverallTotalScore : null,
                secondTermTotalScore: term === '3rd' ? secondTermOverallTotalScore : null,
                cumulativeOverallTotal: cumulativeOverallTotal,
                cumulativeOverallObtainable: cumulativeOverallObtainable,
                cumulativeAverage: overallCumulativeAvg,
                position: position,
            }
        });

    } catch (error) {
        console.error('💥 Endpoint error:', error);
        res.status(500).json({ 
            message: 'Server error',
            error: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// GET CLASS RESULTS AND STUDENT POSITIONS FOR THE AUTHENTICATED TEACHER
app.get('/api/teacher/class-overall-results', authenticateToken, authorizeTeacher, async (req, res) => {
    try {
        // Expecting 'class', 'term', and 'session_id' as query parameters
        const { class: selectedClass, term, session_id } = req.query; // 'class' is a reserved word, so alias it
        const teacherId = req.user.id; // Authenticated teacher's ID from the token

        if (!selectedClass || !term || !session_id) {
            return res.status(400).json({ message: 'Class, Term, and Session ID are required for class results.' });
        }

        const sessionIdNum = parseInt(session_id, 10);
        if (isNaN(sessionIdNum)) {
            return res.status(400).json({ message: 'Session ID must be a valid number.' });
        }

        // Verify if the requesting teacher is assigned to this class
        // Fetch the teacher's assigned class from the 'users' table
        const { data: teacherUser, error: teacherError } = await supabase
            .from('users')
            .select('class')
            .eq('id', teacherId)
            .eq('role', 'teacher') // Ensure the user is actually a teacher
            .single();

        if (teacherError || !teacherUser) {
            console.error('Teacher not found or error fetching teacher class:', teacherError);
            return res.status(500).json({ message: 'Could not verify teacher details or you are not a teacher.' });
        }

        if (teacherUser.class !== selectedClass) {
            return res.status(403).json({ message: 'Access denied: You are not assigned to view results for this class.' });
        }

        // 1. Fetch all students (users with role 'student') belonging to the specified class
        const { data: studentsInClass, error: studentsInClassError } = await supabase
            .from('users') // Correctly use the 'users' table
            .select('id, full_name, class')
            .eq('role', 'student') // Filter for students
            .eq('class', selectedClass); // Filter by the requested class

        if (studentsInClassError) throw studentsInClassError;
        if (!studentsInClass || studentsInClass.length === 0) {
            return res.status(404).json({ message: `No students found with the role 'student' for class ${selectedClass}.` });
        }

        const studentIdsInClass = studentsInClass.map(s => s.id);
        const studentDetailsMap = new Map(studentsInClass.map(s => [s.id, { full_name: s.full_name, class: s.class }]));

        // 2. Fetch all academic results for these students, for the given term and session ID
        const { data: academicResults, error: academicResultsError } = await supabase
            .from('results') // CORRECTED: Use 'results' table based on your CSV
            .select('student_id, total_score') // Only need student_id and total_score for ranking
            .in('student_id', studentIdsInClass)
            .eq('term', term)
            .eq('session_id', sessionIdNum); // Filter by the provided session_id

        if (academicResultsError) throw academicResultsError;

        // 3. Aggregate total scores for each student in the class for the specific term and session
        const studentScores = {};
        studentIdsInClass.forEach(id => {
            studentScores[id] = {
                id: id,
                full_name: studentDetailsMap.get(id)?.full_name || 'Unknown',
                class: studentDetailsMap.get(id)?.class || 'N/A',
                term_total_score: 0,
            };
        });

        // Sum up total_score for each student
        academicResults.forEach(result => {
            if (studentScores[result.student_id]) {
                studentScores[result.student_id].term_total_score += result.total_score;
            }
        });

        // Convert object to array for sorting
        let classRankings = Object.values(studentScores);

        // 4. Sort students by term_total_score (descending) to determine positions
        classRankings.sort((a, b) => b.term_total_score - a.term_total_score);

        // 5. Calculate positions (handling ties)
        let currentRank = 1;
        let previousScore = -1; // Initialize with a score lower than any possible score
        classRankings.forEach((student, index) => {
            if (student.term_total_score !== previousScore) {
                currentRank = index + 1;
            }
            student.position = currentRank;
            previousScore = student.term_total_score;
        });

        res.status(200).json({
            message: 'Class results and positions fetched successfully.',
            class: selectedClass,
            term: term,
            session_id: sessionIdNum,
            results: classRankings
        });

    } catch (error) {
        console.error('Error fetching class overall results and positions:', error);
        res.status(500).json({
            message: 'Failed to fetch class overall results and positions',
            error: error.message
        });
    }
});

// [13] RECORD STUDENT ATTENDANCE (New Endpoint)
app.post('/api/teacher/attendance', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'teacher') return res.status(403).json({ message: 'Unauthorized - Teachers only' });

        const { student_id, term, session, days_opened, days_present } = req.body;

        if (!student_id || !term || !session || days_opened == null || days_present == null) {
            return res.status(400).json({ message: 'Student ID, term, session, days opened, and days present are required.' });
        }

        const { data: student, error: studentError } = await supabase
            .from('users')
            .select('id, class')
            .eq('student_id', student_id)
            .single();
        if (studentError || !student) {
            return res.status(404).json({ message: 'Student not found.' });
        }

        const { data: teacher, error: teacherError } = await supabase
            .from('users')
            .select('class')
            .eq('id', req.user.id)
            .single();
        if (teacherError || !teacher) {
            throw new Error('Teacher not found.');
        }
        if (teacher.class !== student.class) {
            return res.status(403).json({ message: 'Unauthorized - You can only record attendance for students in your assigned class.' });
        }

        let sessionId;
        const { data: existingSession, error: existingSessionError } = await supabase
            .from('sessions')
            .select('id')
            .eq('name', session)
            .single();
        if (existingSession) {
            sessionId = existingSession.id;
        } else {
            const { data: newSession, error: newSessionError } = await supabase
                .from('sessions')
                .insert([{ name: session }])
                .select('id')
                .single();
            if (newSessionError) throw newSessionError;
            sessionId = newSession.id;
        }

        const { data: attendanceRecord, error: attendanceError } = await supabase
            .from('attendance')
            .upsert({
                student_id: student.id,
                term: term,
                session_id: sessionId,
                days_opened: days_opened,
                days_present: days_present,
                recorded_by: req.user.id
            }, {
                onConflict: 'student_id,term,session_id'
            })
            .select()
            .single();

        if (attendanceError) {
            throw new Error('Failed to record attendance.');
        }

        res.status(200).json({
            message: 'Attendance recorded successfully.',
            attendance: attendanceRecord
        });

    } catch (error) {
        res.status(500).json({
            message: 'Failed to record attendance',
            error: error.message
        });
    }
});

// New API to fetch a specific academic result for pre-filling
app.get('/api/teacher/result/:studentId/:subjectId/:term/:session', authenticateToken, async (req, res) => {
    try {
        const { studentId, subjectId, term, session } = req.params;

        const { data: student, error: studentError } = await supabase
            .from('users')
            .select('id')
            .eq('student_id', studentId)
            .single();
        if (studentError || !student) return res.status(404).json({ message: 'Student not found.' });

        const { data: sessionData, error: sessionError } = await supabase
            .from('sessions')
            .select('id')
            .eq('name', session)
            .single();
        if (sessionError || !sessionData) {
            return res.status(404).json({ message: 'Session not found.' });
        }
        const sessionId = sessionData.id;

        const { data, error } = await supabase
            .from('results') // Assuming your table is named 'results'
            .select('pt1, pt2, pt3, exam') // Select only the academic scores for prefill
            .eq('student_id', student.id)
            .eq('subject_id', subjectId)
            .eq('term', term)
            .eq('session_id', sessionId) // Use session_id if your results table stores session as a foreign key
            .single();

        if (error && error.code === 'PGRST116') { // No rows found
            return res.status(404).json({ message: 'No existing academic result found for this student, subject, term, and session.' });
        }
        if (error) throw error;

        res.status(200).json(data);
    } catch (error) {
        console.error('Error fetching academic result for prefill:', error.message);
        res.status(500).json({ message: 'Failed to fetch academic result for prefill', error: error.message });
    }
});

// New API to fetch psychomotor results and attendance data for pre-filling
app.get('/api/teacher/psychomotor/:studentId/:term/:session', authenticateToken, async (req, res) => {
    try {
        const { studentId, term, session } = req.params;

        const { data: student, error: studentError } = await supabase
            .from('users')
            .select('id')
            .eq('student_id', studentId)
            .single();
        if (studentError || !student) return res.status(404).json({ message: 'Student not found.' });

        const { data: sessionData, error: sessionError } = await supabase
            .from('sessions')
            .select('id')
            .eq('name', session)
            .single();
        if (sessionError || !sessionData) {
            return res.status(404).json({ message: 'Session not found.' });
        }
        const sessionId = sessionData.id;

        // Fetch psychomotor data
        const { data: psychomotorData, error: psychomotorError } = await supabase
            .from('psychomotor') // Assuming your table is named 'psychomotor'
            .select('attendance, punctuality, neatness, honesty, responsibility, creativity, sports')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session_id', sessionId) // Use session_id
            .single();

        // Fetch attendance data separately
        const { data: attendanceData, error: attendanceError } = await supabase
            .from('attendance') // Assuming your table is named 'attendance'
            .select('days_opened, days_present')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session_id', sessionId) // Use session_id
            .single();

        if ((psychomotorError && psychomotorError.code !== 'PGRST116') || (attendanceError && attendanceError.code !== 'PGRST116')) {
            // Only throw if it's an actual database error, not just "no rows found"
            if (psychomotorError && psychomotorError.code !== 'PGRST116') throw psychomotorError;
            if (attendanceError && attendanceError.code !== 'PGRST116') throw attendanceError;
        }

        if (!psychomotorData && !attendanceData) {
            return res.status(404).json({ message: 'No existing psychomotor or attendance result found.' });
        }

        // Combine psychomotor and attendance data
        const combinedData = {
            ...(psychomotorData || {}), // Ensure psychomotorData is an object even if null
            ...(attendanceData || {})    // Ensure attendanceData is an object even if null
        };

        res.status(200).json(combinedData);

    } catch (error) {
        console.error('Error fetching psychomotor/attendance result for prefill:', error.message);
        res.status(500).json({ message: 'Failed to fetch psychomotor/attendance result for prefill', error: error.message });
    }
});

// [14] GET CURRENT USER INFO
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', req.user.id)
            .single();
        if (error || !user) throw new Error('User not found');
        delete user.password;
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// ======================
// STUDENT ENDPOINTS
// ======================

// [6] GET STUDENT'S OWN PROFILE
app.get('/api/student/me', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only students can access this endpoint for their own profile
        if (req.user.role !== 'student') {
            return res.status(403).json({ message: 'Unauthorized - Students only' });
        }

        const { data: student, error } = await supabase
            .from('users')
            .select('id, student_id, full_name, email, gender, class, profile_picture, is_active')
            .eq('id', req.user.id) // Fetch data for the authenticated user ID
            .single();

        if (error || !student) {
            console.error('Supabase student lookup error:', error);
            return res.status(404).json({ message: 'Student profile not found.' });
        }

        res.status(200).json({
            message: 'Student profile fetched successfully.',
            student: student
        });

    } catch (error) {
        console.error('Get student profile error:', error);
        res.status(500).json({
            message: 'Failed to fetch student profile',
            error: error.message
        });
    }
});

// [7] GET STUDENT'S OWN ACADEMIC AND PSYCHOMOTOR RESULTS (Enhanced for full report card)
app.get('/api/student/results/:term/:session', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only students can access their own results
        if (req.user.role !== 'student') {
            return res.status(403).json({ message: 'Unauthorized - Students only' });
        }

        const { term, session } = req.params;
        const studentId = req.user.id; // The authenticated student's user ID

        // 1. Fetch the student's basic details (class is crucial for class-based calculations)
        const { data: student, error: studentError } = await supabase
            .from('users')
            .select('id, student_id, full_name, class, gender, profile_picture')
            .eq('id', studentId)
            .single();

        if (studentError || !student) {
            console.error('Supabase student lookup error:', studentError);
            return res.status(404).json({ message: 'Student profile not found.' });
        }

        // 2. Get the session ID from the session name
        const { data: sessionData, error: sessionError } = await supabase
            .from('sessions')
            .select('id')
            .eq('name', session)
            .single();

        if (sessionError || !sessionData) {
            console.error('Supabase session lookup error:', sessionError);
            return res.status(404).json({ message: 'Session not found for the given term/session combination.' });
        }
        const sessionId = sessionData.id;

        // 3. Fetch academic results for the student, term, and session (only approved ones for reports)
        const { data: academicResults, error: resultsError } = await supabase
            .from('results')
            .select(`
                id, pt1, pt2, pt3, avg_pt, exam, total_score, grade, remark, is_approved,
                subject_id, subjects!inner(name)
            `)
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session_id', sessionId)
            .eq('is_approved', true) // Only approved results for the report
            .order('subjects(name)', { ascending: true }); // Order by subject name

        if (resultsError) {
            console.error('Supabase academic results lookup error:', resultsError);
            throw new Error('Failed to fetch academic results.');
        }

        // Prepare enhanced academic results with previous term scores and subject-level class averages
        const enhancedAcademicResults = await Promise.all(academicResults.map(async (result) => {
            let firstTermSubjectTotal = null;
            let secondTermSubjectTotal = null;
            let cumulativeSubjectTotal = result.total_score; // Start with current term's total
            let termsCountForSubjectAvg = 1;

            // Fetch 1st Term Subject Total
            if (term !== '1st') {
                const { data: firstTermRes } = await supabase
                    .from('results')
                    .select('total_score')
                    .eq('student_id', student.id)
                    .eq('subject_id', result.subject_id)
                    .eq('term', '1st')
                    .eq('session_id', sessionId)
                    .eq('is_approved', true)
                    .single();
                if (firstTermRes) {
                    firstTermSubjectTotal = firstTermRes.total_score;
                    cumulativeSubjectTotal += firstTermSubjectTotal;
                    termsCountForSubjectAvg++;
                }
            }

            // Fetch 2nd Term Subject Total (if current term is 3rd)
            if (term === '3rd') {
                const { data: secondTermRes } = await supabase
                    .from('results')
                    .select('total_score')
                    .eq('student_id', student.id)
                    .eq('subject_id', result.subject_id)
                    .eq('term', '2nd')
                    .eq('session_id', sessionId)
                    .eq('is_approved', true)
                    .single();
                if (secondTermRes) {
                    secondTermSubjectTotal = secondTermRes.total_score;
                    cumulativeSubjectTotal += secondTermSubjectTotal;
                    termsCountForSubjectAvg++;
                }
            }
            
            // Calculate Subject-level Class Average for current term
            let subjectClassAverage = 'N/A';
            const { data: classSubjectScores, error: classSubjectScoresError } = await supabase
                .from('results')
                .select(`total_score, students:student_id!inner(class)`)
                .eq('subject_id', result.subject_id)
                .eq('term', term)
                .eq('session_id', sessionId)
                .eq('is_approved', true)
                .eq('students.class', student.class); // Filter by the student's class

            if (classSubjectScoresError) {
                console.error(`Error fetching class scores for subject ${result.subject_name}:`, classSubjectScoresError);
            } else if (classSubjectScores && classSubjectScores.length > 0) {
                const totalScores = classSubjectScores.reduce((sum, s) => sum + s.total_score, 0);
                subjectClassAverage = (totalScores / classSubjectScores.length).toFixed(2);
            }

            return {
                ...result,
                subject_name: result.subjects.name,
                first_term_subject_total: firstTermSubjectTotal,
                second_term_subject_total: secondTermSubjectTotal,
                cumulative_subject_average: termsCountForSubjectAvg > 0 ? (cumulativeSubjectTotal / termsCountForSubjectAvg).toFixed(2) : 'N/A', // Corrected calculation
                subject_class_average: subjectClassAverage,
            };
        }));


        // 4. Fetch psychomotor skills for the student, term, and session
        const { data: psychomotorSkills, error: psychomotorError } = await supabase
            .from('psychomotor')
            .select('attendance, punctuality, neatness, honesty, responsibility, creativity, sports')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session_id', sessionId)
            .single();

        // If psychomotor skills are not found, it's not an error, just return empty object
        if (psychomotorError && psychomotorError.code !== 'PGRST116') { // PGRST116 means 'No rows found'
            console.warn('Warning: Psychomotor skills not found for student, term, session:', psychomotorError.message);
        }

        // 5. Fetch Attendance Data for the student, term, and session
        const { data: attendanceData, error: attendanceError } = await supabase
            .from('attendance')
            .select('days_opened, days_present')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session', session) // Use session name from URL for attendance table
            .single();
        
        if (attendanceError && attendanceError.code !== 'PGRST116') { // Ignore "no rows found"
            console.warn('Warning: Attendance data not found for student, term, session:', attendanceError.message);
        }

        // 6. Calculate Overall Performance for Current Term
        const totalObtainableCurrentTerm = academicResults.length * 100; // Each subject max 100
        const totalScoredCurrentTerm = academicResults.reduce((sum, r) => sum + r.total_score, 0);
        const percentageCurrentTerm = totalObtainableCurrentTerm > 0 ? (totalScoredCurrentTerm / totalObtainableCurrentTerm) * 100 : 0;

        // 7. Calculate Class Average (for overall total score for the term) and Position in Class
        let classAverageOverall = 'N/A'; // This is the class average of *overall* student scores for the term
        let positionInClass = 'N/A';

        if (totalObtainableCurrentTerm > 0) {
            // Fetch all approved results for students in the same class for the current term and session
            const { data: allClassApprovedResults, error: allClassApprovedResultsError } = await supabase
                .from('results')
                .select(`
                    total_score,
                    student_id
                `)
                .eq('term', term)
                .eq('session_id', sessionId)
                .eq('is_approved', true);
            
            if (allClassApprovedResultsError) {
                console.error('Error fetching all class approved results for overall average/position:', allClassApprovedResultsError);
            } else if (allClassApprovedResults && allClassApprovedResults.length > 0) {
                // Get all students in the same class as the current student
                const { data: studentsInClass, error: studentsInClassError } = await supabase
                    .from('users')
                    .select('id, student_id, full_name')
                    .eq('class', student.class)
                    .eq('role', 'student')
                    .eq('is_active', true);

                if (studentsInClassError) {
                    console.error('Error fetching students in class for position:', studentsInClassError);
                } else if (studentsInClass && studentsInClass.length > 0) {
                    const studentOverallScoresInClass = {};
                    studentsInClass.forEach(s => {
                        studentOverallScoresInClass[s.id] = {
                            student_id: s.student_id,
                            full_name: s.full_name,
                            total_score_sum: 0,
                            subject_count: 0
                        };
                    });

                    allClassApprovedResults.forEach(res => {
                        if (studentOverallScoresInClass[res.student_id]) {
                            studentOverallScoresInClass[res.student_id].total_score_sum += res.total_score;
                            studentOverallScoresInClass[res.student_id].subject_count++;
                        }
                    });

                    const studentsWithValidScores = Object.values(studentOverallScoresInClass).filter(s => s.subject_count > 0);

                    if (studentsWithValidScores.length > 0) {
                        const totalClassSumOfScores = studentsWithValidScores.reduce((sum, s) => sum + s.total_score_sum, 0);
                        classAverageOverall = (totalClassSumOfScores / studentsWithValidScores.length).toFixed(2);

                        // Calculate Position in Class
                        studentsWithValidScores.sort((a, b) => b.total_score_sum - a.total_score_sum);

                        let currentRank = 1;
                        let lastScore = -1;
                        for (let i = 0; i < studentsWithValidScores.length; i++) {
                            // Handle ties: students with same score get same rank
                            if (studentsWithValidScores[i].total_score_sum !== lastScore) {
                                currentRank = i + 1;
                                lastScore = studentsWithValidScores[i].total_score_sum;
                            }
                            if (studentsWithValidScores[i].student_id === student.student_id) {
                                positionInClass = `${currentRank} of ${studentsWithValidScores.length}`;
                                break;
                            }
                        }
                    }
                }
            }
        }


        // 8. Cumulative Averages and Previous Term Total Scores (Overall SUM of approved results)
        let firstTermOverallTotalScore = null;
        let secondTermOverallTotalScore = null;
        let cumulativeAveragePercentage = null; // Avg of term overall percentages

        // Fetch overall total scores for previous terms for cumulative average calculation
        const termsForCumulative = [];
        const currentTermPercentage = percentageCurrentTerm;
        if (currentTermPercentage > 0) {
            termsForCumulative.push(currentTermPercentage);
        }

        if (term !== '1st') {
            const { data: firstTermResultsOverall } = await supabase
                .from('results')
                .select('total_score')
                .eq('student_id', student.id)
                .eq('term', '1st')
                .eq('session_id', sessionId)
                .eq('is_approved', true);
            
            if (firstTermResultsOverall && firstTermResultsOverall.length > 0) {
                firstTermOverallTotalScore = firstTermResultsOverall.reduce((sum, r) => sum + r.total_score, 0);
                const firstTermObtainable = firstTermResultsOverall.length * 100;
                if (firstTermObtainable > 0) {
                    termsForCumulative.push((firstTermOverallTotalScore / firstTermObtainable) * 100);
                }
            }

            if (term === '3rd') {
                const { data: secondTermResultsOverall } = await supabase
                    .from('results')
                    .select('total_score')
                    .eq('student_id', student.id)
                    .eq('term', '2nd')
                    .eq('session_id', sessionId)
                    .eq('is_approved', true);

                if (secondTermResultsOverall && secondTermResultsOverall.length > 0) {
                    secondTermOverallTotalScore = secondTermResultsOverall.reduce((sum, r) => sum + r.total_score, 0);
                    const secondTermObtainable = secondTermResultsOverall.length * 100;
                    if (secondTermObtainable > 0) {
                        termsForCumulative.push((secondTermOverallTotalScore / secondTermObtainable) * 100);
                    }
                }
            }
        }
        
        if (termsForCumulative.length > 0) {
            cumulativeAveragePercentage = (termsForCumulative.reduce((sum, p) => sum + p, 0) / termsForCumulative.length).toFixed(2);
        }


        // 9. Determine Teacher Comment and Head Teacher Comment (using percentageCurrentTerm)
        let teacherComment = '';
        if (percentageCurrentTerm >= 70) teacherComment = 'Brilliant student with good potentials, never relent';
        else if (percentageCurrentTerm >= 60) teacherComment = 'This is not yet your limit, you can do more';
        else if (percentageCurrentTerm >= 50) teacherComment = 'Good, but there is a need for serious improvement and seriousness';
        else if (percentageCurrentTerm >= 40) teacherComment = 'Try harder, you have the potentials';
        else if (percentageCurrentTerm >= 30) teacherComment = 'Needs urgent attention and improvement';
        else teacherComment = 'Very poor performance, immediate intervention needed';

        let headTeacherComment = '';
        if (percentageCurrentTerm >= 80) headTeacherComment = 'Outstanding performance! Keep soaring higher. - Mr Olusegun';
        else if (percentageCurrentTerm >= 70) headTeacherComment = 'Excellent result. Maintain this standard. - Mr Olusegun';
        else if (percentageCurrentTerm >= 60) headTeacherComment = 'Excellent performance. Aim for excellence. - Mr Olusegun'; 
        else if (percentageCurrentTerm >= 50) headTeacherComment = 'Satisfactory result. More effort required. - Mr Olusegun';
        else if (percentageCurrentTerm >= 40) headTeacherComment = 'Fair performance. Significant improvement needed. - Mr Olusegun';
        else headTeacherComment = 'Unsatisfactory performance. Immediate remediation required. - Mr Olusegun';


        res.status(200).json({
            message: 'Student results fetched successfully.',
            student: {
                id: student.id,
                student_id: student.student_id,
                full_name: student.full_name,
                class: student.class,
                gender: student.gender,
                profile_picture: student.profile_picture
            },
            term,
            session,
            academicResults: enhancedAcademicResults, // Send the enhanced results
            psychomotor: psychomotorSkills || {},
            attendance: attendanceData || { days_opened: 'N/A', days_present: 'N/A' }, // Ensure it's never null
            overallPerformance: {
                totalObtainable: totalObtainableCurrentTerm,
                totalScored: totalScoredCurrentTerm,
                percentage: parseFloat(percentageCurrentTerm.toFixed(2)),
                classAverage: classAverageOverall, // Overall Class Average for the term
                gradeOfPercentage: (() => { // Grade based on percentage
                    if (percentageCurrentTerm >= 70) return 'A';
                    if (percentageCurrentTerm >= 60) return 'B';
                    if (percentageCurrentTerm >= 50) return 'C';
                    if (percentageCurrentTerm >= 40) return 'D';
                    if (percentageCurrentTerm >= 30) return 'E';
                    return 'F';
                })(),
                positionInClass: positionInClass, // Student's position in class
                teacherComment,
                headTeacherComment
            },
            cumulativeData: {
                firstTermOverallTotalScore: firstTermOverallTotalScore,
                secondTermOverallTotalScore: secondTermOverallTotalScore,
                cumulativeAveragePercentage: cumulativeAveragePercentage, // Cumulative average of percentages
            }
        });

    } catch (error) {
        console.error('Get student results error:', error);
        res.status(500).json({
            message: 'Failed to fetch student results',
            error: error.message
        });
    }
});

// [7a] GET STUDENT'S NOTIFICATIONS
app.get('/api/student/notifications', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only students can access their own notifications
        if (req.user.role !== 'student') {
            return res.status(403).json({ message: 'Unauthorized - Students only' });
        }

        const studentId = req.user.id;

        const { data: notifications, error } = await supabase
            .from('notifications')
            .select('*')
            .eq('recipient_id', studentId)
            .order('created_at', { ascending: false }); // Latest notifications first

        if (error) {
            console.error('Supabase fetch notifications error:', error);
            throw new Error('Failed to fetch notifications.');
        }

        res.status(200).json({
            message: 'Notifications fetched successfully.',
            notifications: notifications || []
        });

    } catch (error) {
        console.error('Get student notifications error:', error);
        res.status(500).json({
            message: 'Failed to fetch notifications',
            error: error.message
        });
    }
});

// [7b] MARK STUDENT NOTIFICATION AS READ
app.patch('/api/student/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        // Authorization check
        if (req.user.role !== 'student') {
            return res.status(403).json({ message: 'Unauthorized - Students only' });
        }

        const notificationId = req.params.id;
        const studentId = req.user.id;

        // Ensure the notification belongs to the authenticated student
        const { data: existingNotification, error: fetchError } = await supabase
            .from('notifications')
            .select('id, recipient_id')
            .eq('id', notificationId)
            .single();

        if (fetchError || !existingNotification) {
            return res.status(404).json({ message: 'Notification not found.' });
        }

        if (existingNotification.recipient_id !== studentId) {
            return res.status(403).json({ message: 'Unauthorized - You can only mark your own notifications as read.' });
        }

        const { data, error } = await supabase
            .from('notifications')
            .update({ is_read: true })
            .eq('id', notificationId)
            .select()
            .single();

        if (error) {
            console.error('Supabase mark as read error:', error);
            throw new Error('Failed to update notification status.');
        }

        res.status(200).json({
            message: 'Notification marked as read.',
            notification: data
        });

    } catch (error) {
        console.error('Mark notification as read error:', error);
        res.status(500).json({
            message: 'Failed to mark notification as read',
            error: error.message
        });
    }
});

// [7c] GET STUDENT'S OWN ATTENDANCE
app.get('/api/student/attendance/:term/:session', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only students can access their own attendance
        if (req.user.role !== 'student') {
            return res.status(403).json({ message: 'Unauthorized - Students only' });
        }

        const { term, session } = req.params;
        const studentId = req.user.id; // The authenticated student's user ID

       // First, fetch the session ID from the session name (like you do in your results endpoint)
const { data: sessionData, error: sessionError } = await supabase
    .from('sessions')
    .select('id')
    .eq('name', session)
    .single();

if (sessionError || !sessionData) {
    // handle error
}
const sessionId = sessionData.id;

const { data: attendance, error } = await supabase
    .from('attendance')
    .select('days_opened, days_present, created_at')
    .eq('student_id', studentId)
    .eq('term', term)
    .eq('session_id', sessionId) // CORRECT
    .single();
        if (error) {
            // If no record found, it's not necessarily an error, just means no data yet
            if (error.code === 'PGRST116') { // PGRST116 means 'No rows found'
                return res.status(200).json({
                    message: 'No attendance data found for this term and session.',
                    attendance: null
                });
            }
            console.error('Supabase fetch attendance error:', error);
            throw new Error('Failed to fetch attendance data.');
        }

        res.status(200).json({
            message: 'Attendance data fetched successfully.',
            attendance: attendance
        });

    } catch (error) {
        console.error('Get student attendance error:', error);
        res.status(500).json({
            message: 'Failed to fetch attendance data',
            error: error.message
        });
    }
});

// [7d] EXPORT STUDENT'S RESULT TO PDF
app.get('/api/student/export-result/:term/:session', authenticateToken, async (req, res) => {
    console.log('--- STUDENT EXPORT RESULT ROUTE HIT ---');
    try {
        // Authorization check - only students can export their own results
        if (req.user.role !== 'student') {
            return res.status(403).json({ message: 'Unauthorized - Students only' });
        }

        const { term, session } = req.params;
        const studentUserId = req.user.id; // The authenticated student's user ID

        // Define PDF dimensions and styles here, globally within the route handler
        const pageSize = [595, 842]; // A4 size
        const margin = 30;
        const tableHeaderHeight = 20;
        const rowHeight = 15;
        const psychomotorRowHeight = 15; // Same as rowHeight for consistency
        const academicColumnWidthsPdf = [
            60,  // Subject
            28,  // PT1
            28,  // PT2
            28,  // PT3
            35,  // Avg PT
            30,  // Exam
            35,  // Total
            45,  // 1st Term Total
            45,  // 2nd Term Total
            45,  // Cum Avg (Subj)
            45,  // Class Avg (Subj)
            28,  // Grade
            60   // Remark
        ];
        const psychomotorColumnWidths = [100, 50]; 
        const attendanceColumnWidths = [150, 80];

        // 1. Fetch Student's Profile
        const { data: student, error: studentError } = await supabase
            .from('users')
            .select('id, student_id, full_name, class, gender, profile_picture')
            .eq('id', studentUserId)
            .single();

        if (studentError || !student) {
            console.error('Supabase student profile lookup error:', studentError);
            return res.status(404).json({ message: 'Student profile not found.' });
        }

        // 2. Fetch School Information
        // Use a direct fetch to the school-info endpoint
        const schoolInfoResponse = await _fetchApi(`http://localhost:${PORT}/api/school-info`);
        if (!schoolInfoResponse.ok) {
            throw new Error(`Failed to fetch school information: ${schoolInfoResponse.status} ${schoolInfoResponse.statusText}`);
        }
        const schoolInfo = await schoolInfoResponse.json();

        // 3. Get Session ID from session name
        const { data: sessionData, error: sessionError } = await supabase
            .from('sessions')
            .select('id')
            .eq('name', session)
            .single();

        if (sessionError || !sessionData) {
            return res.status(404).json({ message: 'Session not found for the given term/session combination.' });
        }
        const sessionId = sessionData.id;

        // 4. Fetch Academic Results (only approved ones)
        const { data: academicResults, error: resultsError } = await supabase
            .from('results')
            .select(`
                id, pt1, pt2, pt3, avg_pt, exam, total_score, grade, remark, is_approved,
                subject_id, subjects!inner(name)
            `)
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session_id', sessionId)
            .eq('is_approved', true) // Only approved results for the report
            .order('subjects(name)', { ascending: true });

        if (resultsError) {
            console.error('Supabase academic results lookup error:', resultsError);
            throw new Error('Failed to fetch academic results for export.');
        }

        // Prepare enhanced academic results with previous term scores and subject-level class averages for PDF
        const enhancedAcademicResultsForPdf = await Promise.all(academicResults.map(async (result) => {
            let firstTermSubjectTotal = null;
            let secondTermSubjectTotal = null;
            let cumulativeSubjectTotal = result.total_score; // Start with current term's total
            let termsCountForSubjectAvg = 1;

            // Fetch 1st Term Subject Total
            if (term !== '1st') {
                const { data: firstTermRes } = await supabase
                    .from('results')
                    .select('total_score')
                    .eq('student_id', student.id)
                    .eq('subject_id', result.subject_id)
                    .eq('term', '1st')
                    .eq('session_id', sessionId)
                    .eq('is_approved', true)
                    .single();
                if (firstTermRes) {
                    firstTermSubjectTotal = firstTermRes.total_score;
                    cumulativeSubjectTotal += firstTermSubjectTotal;
                    termsCountForSubjectAvg++;
                }
            }

            // Fetch 2nd Term Subject Total (if current term is 3rd)
            if (term === '3rd') {
                const { data: secondTermRes } = await supabase
                    .from('results')
                    .select('total_score')
                    .eq('student_id', student.id)
                    .eq('subject_id', result.subject_id)
                    .eq('term', '2nd')
                    .eq('session_id', sessionId)
                    .eq('is_approved', true)
                    .single();
                if (secondTermRes) {
                    secondTermSubjectTotal = secondTermRes.total_score;
                    cumulativeSubjectTotal += secondTermSubjectTotal;
                    termsCountForSubjectAvg++;
                }
            }
            
            // Calculate Subject-level Class Average for current term
            let subjectClassAverage = 'N/A';
            const { data: classSubjectScores, error: classSubjectScoresError } = await supabase
                .from('results')
                .select(`total_score, students:student_id!inner(class)`)
                .eq('subject_id', result.subject_id)
                .eq('term', term)
                .eq('session_id', sessionId)
                .eq('is_approved', true)
                .eq('students.class', student.class); // Filter by the student's class

            if (classSubjectScoresError) {
                console.error(`Error fetching class scores for subject ${result.subjects.name}:`, classSubjectScoresError);
            } else if (classSubjectScores && classSubjectScores.length > 0) {
                const totalScores = classSubjectScores.reduce((sum, s) => sum + s.total_score, 0);
                subjectClassAverage = (totalScores / classSubjectScores.length).toFixed(2);
            }

            return {
                ...result,
                subject_name: result.subjects.name,
                first_term_subject_total: firstTermSubjectTotal,
                second_term_subject_total: secondTermSubjectTotal,
                cumulative_subject_average: termsCountForSubjectAvg > 0 ? (cumulativeSubjectTotal / termsCountForSubjectAvg).toFixed(2) : 'N/A', 
                subject_class_average: subjectClassAverage,
            };
        }));


        // 5. Fetch Psychomotor Skills
        const { data: psychomotorSkills, error: psychomotorError } = await supabase
            .from('psychomotor')
            .select('attendance, punctuality, neatness, honesty, responsibility, creativity, sports')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session_id', sessionId)
            .single();
        if (psychomotorError && psychomotorError.code !== 'PGRST116') { 
            console.warn('Warning: Psychomotor skills not found for student for export:', psychomotorError.message);
        }

        // 6. Fetch Attendance Data - IMPORTANT: Use session_id here
        const { data: attendanceData, error: attendanceError } = await supabase
            .from('attendance')
            .select('days_opened, days_present')
            .eq('student_id', student.id)
            .eq('term', term)
            .eq('session_id', sessionId) // Corrected to use session_id
            .single();
        if (attendanceError && attendanceError.code !== 'PGRST116') { 
            console.warn('Warning: Attendance data not found for student for export:', attendanceError.message);
        }

        // Calculate Overall Performance for Current Term
        const totalObtainableCurrentTerm = academicResults.length * 100;
        const totalScoredCurrentTerm = academicResults.reduce((sum, r) => sum + r.total_score, 0);
        const percentageCurrentTerm = totalObtainableCurrentTerm > 0 ? (totalScoredCurrentTerm / totalObtainableCurrentTerm) * 100 : 0;

        // Calculate Class Average (for overall total score for the term) and Position in Class
        let classAverageOverall = 'N/A';
        let positionInClass = 'N/A';

        if (totalObtainableCurrentTerm > 0) {
            const { data: allClassApprovedResults, error: allClassApprovedResultsError } = await supabase
                .from('results')
                .select(`
                    total_score,
                    student_id
                `)
                .eq('term', term)
                .eq('session_id', sessionId)
                .eq('is_approved', true);
            
            if (allClassApprovedResultsError) {
                console.error('Error fetching all class approved results for overall average/position:', allClassApprovedResultsError);
            } else if (allClassApprovedResults && allClassApprovedResults.length > 0) {
                const { data: studentsInClass, error: studentsInClassError } = await supabase
                    .from('users')
                    .select('id, student_id, full_name')
                    .eq('class', student.class)
                    .eq('role', 'student')
                    .eq('is_active', true);

                if (studentsInClassError) {
                    console.error('Error fetching students in class for position:', studentsInClassError);
                } else if (studentsInClass && studentsInClass.length > 0) {
                    const studentOverallScoresInClass = {};
                    studentsInClass.forEach(s => {
                        studentOverallScoresInClass[s.id] = {
                            student_id: s.student_id,
                            full_name: s.full_name,
                            total_score_sum: 0,
                            subject_count: 0
                        };
                    });

                    allClassApprovedResults.forEach(res => {
                        if (studentOverallScoresInClass[res.student_id]) {
                            studentOverallScoresInClass[res.student_id].total_score_sum += res.total_score;
                            studentOverallScoresInClass[res.student_id].subject_count++;
                        }
                    });

                    const studentsWithValidScores = Object.values(studentOverallScoresInClass).filter(s => s.subject_count > 0);
                    
                    if (studentsWithValidScores.length > 0) {
                        const totalClassSumOfScores = studentsWithValidScores.reduce((sum, s) => sum + s.total_score_sum, 0);
                        classAverageOverall = (totalClassSumOfScores / studentsWithValidScores.length).toFixed(2);

                        studentsWithValidScores.sort((a, b) => b.total_score_sum - a.total_score_sum);

                        let currentRank = 1;
                        let lastScore = -1;
                        for (let i = 0; i < studentsWithValidScores.length; i++) {
                            if (studentsWithValidScores[i].total_score_sum !== lastScore) {
                                currentRank = i + 1;
                                lastScore = studentsWithValidScores[i].total_score_sum;
                            }
                            if (studentsWithValidScores[i].student_id === student.student_id) {
                                positionInClass = `${currentRank} of ${studentsWithValidScores.length}`;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Cumulative Averages (Overall) and Previous Term Total Scores (Overall SUM of approved results)
        let firstTermOverallTotalScore = null;
        let secondTermOverallTotalScore = null;
        let cumulativeAveragePercentage = null; // Avg of term overall percentages

        const termsForCumulative = [];
        const currentTermPercentageValue = parseFloat(percentageCurrentTerm.toFixed(2));
        if (!isNaN(currentTermPercentageValue) && currentTermPercentageValue > 0) {
            termsForCumulative.push(currentTermPercentageValue);
        }

        if (term !== '1st') {
            const { data: firstTermResultsOverall } = await supabase
                .from('results')
                .select('total_score')
                .eq('student_id', student.id)
                .eq('term', '1st')
                .eq('session_id', sessionId)
                .eq('is_approved', true);
            
            if (firstTermResultsOverall && firstTermResultsOverall.length > 0) {
                firstTermOverallTotalScore = firstTermResultsOverall.reduce((sum, r) => sum + r.total_score, 0);
                const firstTermObtainable = firstTermResultsOverall.length * 100;
                if (firstTermObtainable > 0) {
                    termsForCumulative.push((firstTermOverallTotalScore / firstTermObtainable) * 100);
                }
            }

            if (term === '3rd') {
                const { data: secondTermResultsOverall } = await supabase
                    .from('results')
                    .select('total_score')
                    .eq('student_id', student.id)
                    .eq('term', '2nd')
                    .eq('session_id', sessionId)
                    .eq('is_approved', true);

                if (secondTermResultsOverall && secondTermResultsOverall.length > 0) {
                    secondTermOverallTotalScore = secondTermResultsOverall.reduce((sum, r) => sum + r.total_score, 0);
                    const secondTermObtainable = secondTermResultsOverall.length * 100;
                    if (secondTermObtainable > 0) {
                        termsForCumulative.push((secondTermOverallTotalScore / secondTermObtainable) * 100);
                    }
                }
            }
        }
        
        if (termsForCumulative.length > 0) {
            cumulativeAveragePercentage = (termsForCumulative.reduce((sum, p) => sum + p, 0) / termsForCumulative.length).toFixed(2);
        }

        // Determine Teacher Comment and Head Teacher Comment (using percentageCurrentTerm)
        let teacherComment = '';
        if (percentageCurrentTerm >= 70) teacherComment = 'Brilliant student with good potentials, never relent';
        else if (percentageCurrentTerm >= 60) teacherComment = 'This is not yet your limit, you can do more';
        else if (percentageCurrentTerm >= 50) teacherComment = 'Good, but there is a need for serious improvement and seriousness';
        else if (percentageCurrentTerm >= 40) teacherComment = 'Try harder, you have the potentials';
        else if (percentageCurrentTerm >= 30) teacherComment = 'Needs urgent attention and improvement';
        else teacherComment = 'Very poor performance, immediate intervention needed';

        let headTeacherComment = '';
        if (percentageCurrentTerm >= 80) headTeacherComment = 'Outstanding performance! Keep soaring higher. - Mr Olusegun';
        else if (percentageCurrentTerm >= 70) headTeacherComment = 'Excellent result. Maintain this standard. - Mr Olusegun';
        else if (percentageCurrentTerm >= 60) headTeacherComment = 'Excellent performance. Aim for excellence. - Mr Olusegun'; 
        else if (percentageCurrentTerm >= 50) headTeacherComment = 'Satisfactory result. More effort required. - Mr Olusegun';
        else if (percentageCurrentTerm >= 40) headTeacherComment = 'Fair performance. Significant improvement needed. - Mr Olusegun';
        else headTeacherComment = 'Unsatisfactory performance. Immediate remediation required. - Mr Olusegun';


        // --- PDF Generation Logic ---
        const pdfDoc = await PDFDocument.create();
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

        let logoImage = null;
        // Construct the full path to the logo in Supabase Storage. Use static path "school_logos/logo.png"
        const logoStoragePath = `${process.env.SUPABASE_URL}/storage/v1/object/public/school-media/logo.png`;

        try {
            const logoResponse = await _fetchApi(logoStoragePath);
            if (logoResponse.ok) {
                const logoBytes = await logoResponse.arrayBuffer();
                logoImage = await pdfDoc.embedPng(logoBytes); 
                console.log('Logo embedded successfully from storage URL.');
            } else {
                console.warn(`Failed to fetch logo from ${logoStoragePath}: ${logoResponse.status} ${logoResponse.statusText}`);
            }
        } catch (logoErr) {
            console.warn('Could not embed logo for PDF (fetch error):', logoErr.message);
            logoImage = null;
        }

        let studentProfilePicture = null;
        if (student.profile_picture) {
            try {
                const picResponse = await _fetchApi(student.profile_picture);
                if (picResponse.ok) {
                    const picBytes = await picResponse.arrayBuffer();
                    const imageType = student.profile_picture.endsWith('.png') ? 'image/png' : 'image/jpeg';
                    studentProfilePicture = imageType === 'image/png'
                        ? await pdfDoc.embedPng(picBytes)
                        : await pdfDoc.embedJpg(picBytes);
                } else {
                    console.warn(`Failed to fetch student picture: ${picResponse.status} ${picResponse.statusText}`);
                }
            } catch (picErr) {
                console.warn('Could not embed student picture for PDF:', picErr.message);
                studentProfilePicture = null;
            }
        }
        
        let yPosition;
        let currentPage;

        const addPageHeader = () => {
            currentPage = pdfDoc.addPage(pageSize);
            yPosition = pageSize[1] - margin;

            // --- Watermark ---
            if (logoImage) {
                const logoAspectRatio = logoImage.width / logoImage.height;
                const pageContentWidth = pageSize[0] - (2 * margin);
                const pageContentHeight = pageSize[1] - (2 * margin);
                let watermarkWidth = pageContentWidth * 0.7; 
                let watermarkHeight = watermarkWidth / logoAspectRatio;
                if (watermarkHeight > pageContentHeight * 0.7) {
                    watermarkHeight = pageContentHeight * 0.7;
                    watermarkWidth = watermarkHeight * logoAspectRatio;
                }
                const watermarkX = (pageSize[0] - watermarkWidth) / 2;
                const watermarkY = (pageSize[1] - watermarkHeight) / 2;
                currentPage.drawImage(logoImage, {
                    x: watermarkX,
                    y: watermarkY,
                    width: watermarkWidth,
                    height: watermarkHeight,
                    opacity: 0.1, 
                });
            }

            // --- Regular Header Content (School Info) ---
            currentPage.drawText(schoolInfo.name.toUpperCase(), {
                x: margin, y: pageSize[1] - margin, font: boldFont, size: 16, color: rgb(0.1, 0.1, 0.4),
            });
            currentPage.drawText(schoolInfo.motto, {
                x: margin, y: pageSize[1] - margin - 15, font: font, size: 10, color: rgb(0.3, 0.3, 0.3),
            });
            currentPage.drawText(`Address: ${schoolInfo.address}`, {
                x: margin, y: pageSize[1] - margin - 35, font: font, size: 8, color: rgb(0.2, 0.2, 0.2),
            });
            currentPage.drawText(`Phone: ${schoolInfo.phone} | Email: ${schoolInfo.email}`, {
                x: margin, y: pageSize[1] - margin - 45, font: font, size: 8, color: rgb(0.2, 0.2, 0.2),
            });

            yPosition = pageSize[1] - margin - 70; 
        };

        addPageHeader(); // Add first page header

        currentPage.drawText(`Student Result Sheet - ${term} Term, ${session} Session`, {
            x: margin, y: yPosition, font: boldFont, size: 14, color: rgb(0, 0, 0),
        });
        yPosition -= 20;

        // Student Details Section
        if (studentProfilePicture) {
            currentPage.drawImage(studentProfilePicture, {
                x: margin + 450, y: yPosition - 30, width: 60, height: 60,
            });
        }
        currentPage.drawText(`Name: ${student.full_name}`, { x: margin, y: yPosition - 10, font: font, size: 10 });
        currentPage.drawText(`Student ID: ${student.student_id}`, { x: margin, y: yPosition - 25, font: font, size: 10 });
        currentPage.drawText(`Class: ${student.class}`, { x: margin, y: yPosition - 40, font: font, size: 10 });
        currentPage.drawText(`Gender: ${student.gender}`, { x: margin, y: yPosition - 55, font: font, size: 10 });
        yPosition -= 80;

        // Academic Performance Table
        currentPage.drawText('Academic Performance:', { x: margin, y: yPosition, font: boldFont, size: 11 });
        yPosition -= 15;

        let x = margin;
        const academicHeaders = ['Subject', 'PT1', 'PT2', 'PT3', 'Avg PT', 'Exam', 'Total', '1st Term Total', '2nd Term Total', 'Cum Avg (Subj)', 'Class Avg (Subj)', 'Grade', 'Remark'];
        
        let currentHeaderX = margin;
        let tableWidth = academicColumnWidthsPdf.reduce((sum, w) => sum + w, 0);

        // Draw header background
        currentPage.drawRectangle({
            x: currentHeaderX, y: yPosition - tableHeaderHeight, width: tableWidth, height: tableHeaderHeight, color: rgb(0.9, 0.9, 0.95),
        });

        // Draw headers
        academicHeaders.forEach((header, index) => {
            currentPage.drawText(header, {
                x: currentHeaderX + 2, // Slight padding
                y: yPosition - tableHeaderHeight + 5,
                font: boldFont,
                size: 6, // Reduced font size to fit more columns
                color: rgb(0, 0, 0),
            });
            currentHeaderX += academicColumnWidthsPdf[index];
        });
        yPosition -= tableHeaderHeight;

        for (const res of enhancedAcademicResultsForPdf) {
            // Check if new page is needed before drawing a new row
            if (yPosition < margin + rowHeight) { 
                addPageHeader();
                currentPage.drawText('Academic Performance (Continued):', { x: margin, y: yPosition, font: boldFont, size: 11 });
                yPosition -= 15;
                currentHeaderX = margin;
                currentPage.drawRectangle({
                    x: currentHeaderX, y: yPosition - tableHeaderHeight, width: tableWidth, height: tableHeaderHeight, color: rgb(0.9, 0.9, 0.95),
                });
                academicHeaders.forEach((header, index) => {
                    currentPage.drawText(header, {
                        x: currentHeaderX + 2, 
                        y: yPosition - tableHeaderHeight + 5, 
                        font: boldFont, 
                        size: 6, 
                        color: rgb(0, 0, 0),
                    });
                    currentHeaderX += academicColumnWidthsPdf[index];
                });
                yPosition -= tableHeaderHeight;
            }

            x = margin;
            const rowValues = [
                res.subject_name, 
                res.pt1, 
                res.pt2, 
                res.pt3, 
                res.avg_pt, 
                res.exam, 
                res.total_score,
                res.first_term_subject_total || '-', // Display '-' if not applicable
                res.second_term_subject_total || '-', // Display '-' if not applicable
                res.cumulative_subject_average || '-', // Display '-' if not applicable
                res.subject_class_average || '-', // Display '-' if not applicable
                res.grade, 
                res.remark
            ];
            rowValues.forEach((val, index) => {
                currentPage.drawText(String(val), {
                    x: x + 2, // Small padding
                    y: yPosition - rowHeight + 5, 
                    font: font, 
                    size: 7, // Smaller font size for row values
                    color: rgb(0, 0, 0),
                });
                x += academicColumnWidthsPdf[index];
            });
            yPosition -= rowHeight;
        }
        yPosition -= 10; 

        // Psychomotor Skills
        if (psychomotorSkills && Object.keys(psychomotorSkills).length > 0) {
            if (yPosition < margin + (psychomotorRowHeight * 7) + 30) { // Estimate space needed
                addPageHeader();
            }
            currentPage.drawText('Psychomotor Skills:', { x: margin, y: yPosition, font: boldFont, size: 11 });
            yPosition -= 15;

            const psychomotorHeaders = ['Attribute', 'Score'];
            
            x = margin;
            currentPage.drawRectangle({
                x: x, y: yPosition - tableHeaderHeight, width: psychomotorColumnWidths.reduce((sum, w) => sum + w, 0), height: tableHeaderHeight, color: rgb(0.9, 0.95, 0.9),
            });
            psychomotorHeaders.forEach((header, index) => {
                currentPage.drawText(header, {
                    x: x + 5, y: yPosition - tableHeaderHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0),
                });
                x += psychomotorColumnWidths[index];
            });
            yPosition -= tableHeaderHeight;

            const psychomotorAttributes = [
                { name: 'Attendance', score: psychomotorSkills.attendance },
                { name: 'Punctuality', score: psychomotorSkills.punctuality },
                { name: 'Neatness', score: psychomotorSkills.neatness },
                { name: 'Honesty', score: psychomotorSkills.honesty },
                { name: 'Responsibility', score: psychomotorSkills.responsibility },
                { name: 'Creativity', score: psychomotorSkills.creativity },
                { name: 'Sports', score: psychomotorSkills.sports }
            ];

            for (const attr of psychomotorAttributes) {
                if (yPosition < margin + psychomotorRowHeight) {
                    addPageHeader();
                    currentPage.drawText('Psychomotor Skills (Continued):', { x: margin, y: yPosition, font: boldFont, size: 11 });
                    yPosition -= 15;
                    x = margin;
                    currentPage.drawRectangle({
                        x: x, y: yPosition - tableHeaderHeight, width: psychomotorColumnWidths.reduce((sum, w) => sum + w, 0), height: tableHeaderHeight, color: rgb(0.9, 0.95, 0.9),
                    });
                    psychomotorHeaders.forEach((header, index) => {
                        currentPage.drawText(header, { x: x + 5, y: yPosition - tableHeaderHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0) });
                        x += psychomotorColumnWidths[index];
                    });
                    yPosition -= tableHeaderHeight;
                }
                
                x = margin;
                currentPage.drawText(attr.name, {
                    x: x + 5, y: yPosition - psychomotorRowHeight + 5, font: font, size: 8, color: rgb(0, 0, 0),
                });
                x += psychomotorColumnWidths[0];
                currentPage.drawText(String(attr.score), {
                    x: x + 5, y: yPosition - psychomotorRowHeight + 5, font: font, size: 8, color: rgb(0, 0, 0),
                });
                yPosition -= psychomotorRowHeight;
            }
            yPosition -= 10;
        }

        // Attendance Data
        if (attendanceData && attendanceData.days_opened !== 'N/A' && attendanceData.days_present !== 'N/A') {
            if (yPosition < margin + (rowHeight * 3) + 15) { // Estimate space needed
                addPageHeader();
            }
            currentPage.drawText('Attendance:', { x: margin, y: yPosition, font: boldFont, size: 11 });
            yPosition -= 15;

            x = margin;
            currentPage.drawRectangle({
                x: x, y: yPosition - tableHeaderHeight, width: attendanceColumnWidths.reduce((sum, w) => sum + w, 0), height: tableHeaderHeight, color: rgb(0.95, 0.9, 0.9),
            });
            const attendanceHeaders = ['Total Days Opened', 'Days Present'];
            attendanceHeaders.forEach((header, index) => {
                currentPage.drawText(header, {
                    x: x + 5, y: yPosition - tableHeaderHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0),
                });
                x += attendanceColumnWidths[index];
            });
            yPosition -= tableHeaderHeight;

            x = margin;
            currentPage.drawText(String(attendanceData.days_opened), {
                x: x + 5, y: yPosition - rowHeight + 5, font: font, size: 8, color: rgb(0, 0, 0),
            });
            x += attendanceColumnWidths[0];
            currentPage.drawText(String(attendanceData.days_present), {
                x: x + 5, y: yPosition - rowHeight + 5, font: font, size: 8, color: rgb(0, 0, 0),
            });
            yPosition -= rowHeight;
            yPosition -= 10;
        }
        
        // Overall Performance Summary & Comments
        if (yPosition < margin + 180) { // Estimate space for summary and comments (increased estimate)
            addPageHeader();
        }

        currentPage.drawText('Overall Performance Summary:', { x: margin, y: yPosition, font: boldFont, size: 11 });
        yPosition -= 15;

        // Current Term Score Summary
        currentPage.drawText(`Current Term Score Summary:`, { x: margin, y: yPosition, font: boldFont, size: 10 });
        currentPage.drawText(`- Total Score Obtained: ${totalScoredCurrentTerm}`, { x: margin + 10, y: yPosition - 15, font: font, size: 9 });
        currentPage.drawText(`- Total Score Obtainable: ${totalObtainableCurrentTerm}`, { x: margin + 10, y: yPosition - 30, font: font, size: 9 });
        currentPage.drawText(`- Percentage: ${percentageCurrentTerm.toFixed(2)}%`, { x: margin + 10, y: yPosition - 45, font: boldFont, size: 10, color: rgb(0, 0.5, 0) });
        currentPage.drawText(`- Grade: ${(() => { // Grade based on percentage
                    if (percentageCurrentTerm >= 70) return 'A';
                    if (percentageCurrentTerm >= 60) return 'B';
                    if (percentageCurrentTerm >= 50) return 'C';
                    if (percentageCurrentTerm >= 40) return 'D';
                    if (percentageCurrentTerm >= 30) return 'E';
                    return 'F';
                })()}`, { x: margin + 10, y: yPosition - 60, font: boldFont, size: 10, color: rgb(0.2, 0.2, 0.8) });
        yPosition -= 75; // Move Y down after this block

        // Class Performance & Position
        currentPage.drawText('Class Performance & Position:', { x: margin, y: yPosition, font: boldFont, size: 10 });
        currentPage.drawText(`- Class Average (Overall for term): ${classAverageOverall}`, { x: margin + 10, y: yPosition - 15, font: font, size: 9 });
        currentPage.drawText(`- Position in Class: ${positionInClass}`, { x: margin + 10, y: yPosition - 30, font: boldFont, size: 10, color: rgb(0.2, 0.6, 0.2) });
        yPosition -= 45; // Move Y down after this block

        // Cumulative Term Averages
        if (term !== '1st') {
            currentPage.drawText('Cumulative Term Averages:', { x: margin, y: yPosition, font: boldFont, size: 10 });
            if (term === '2nd' || term === '3rd') {
                currentPage.drawText(`- 1st Term Overall Total Score: ${firstTermOverallTotalScore !== null ? firstTermOverallTotalScore : 'N/A'}`, { x: margin + 10, y: yPosition - 15, font: font, size: 9 });
                yPosition -= 15;
            }
            if (term === '3rd') {
                currentPage.drawText(`- 2nd Term Overall Total Score: ${secondTermOverallTotalScore !== null ? secondTermOverallTotalScore : 'N/A'}`, { x: margin + 10, y: yPosition - 15, font: font, size: 9 });
                yPosition -= 15;
            }
            currentPage.drawText(`- Cumulative Average: ${cumulativeAveragePercentage !== null ? cumulativeAveragePercentage : 'N/A'}%`, { x: margin + 10, y: yPosition - 15, font: boldFont, size: 10, color: rgb(0.4, 0.1, 0.6) });
            yPosition -= 30; // Move Y down after this block
        }

        // Comments
        currentPage.drawText('Comments:', { x: margin, y: yPosition, font: boldFont, size: 11 });
        yPosition -= 15;
        currentPage.drawText(`Teacher's Comment: ${teacherComment}`, {
            x: margin, y: yPosition, font: font, size: 9, color: rgb(0.2, 0.2, 0.2),
        });
        currentPage.drawText(`Head Teacher's Comment: ${headTeacherComment}`, {
            x: margin, y: yPosition - 15, font: font, size: 9, color: rgb(0.2, 0.2, 0.2),
        });
        yPosition -= 40; // Space after comments

        // Finalize PDF
        const pdfBytes = await pdfDoc.save();

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${student.full_name.replace(/\s/g, '_')}_${term}_${session}_result.pdf"`);
        res.send(Buffer.from(pdfBytes));

    } catch (error) {
        console.error('Student export result error:', error);
        res.status(500).json({
            message: 'Failed to export student result',
            error: error.message
        });
    }
});

// [14] GET CURRENT USER INFO
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (error || !user) throw new Error('User not found');

    // Remove sensitive data
    delete user.password;
    
    res.json(user);
  } catch (error) {
    console.error('User info error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// ======================
// ADMIN ENDPOINTS
// ======================

// [15] ADMIN CREATE USERS (ALL TYPES)
app.post('/api/admin/users', authenticateToken, upload.single('picture'), async (req, res) => {
    try {
        // Authorization check - only admins can access
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        const { userType, ...userData } = req.body;
        const pictureFile = req.file;

        // Validate required fields based on user type
        let validationError;
        switch (userType) {
            case 'admin':
                if (!userData.email || !userData.password || !userData.gender || !userData.full_name) {
                    validationError = 'Admin requires email, password, gender, and full_name';
                }
                break;
            case 'teacher':
                if (!userData.email || !userData.password || !userData.gender || !userData.full_name || !userData.class) {
                    validationError = 'Teacher requires email, password, gender, full_name, and class';
                }
                break;
            case 'student':
                if (!userData.student_id || !userData.password || !userData.gender || !userData.full_name || !userData.class || !pictureFile) {
                    validationError = 'Student requires student_id, password, gender, full_name, class, and picture';
                }
                break;
            default:
                return res.status(400).json({ message: 'Invalid user type. Must be admin, teacher, or student' });
        }

        if (validationError) {
            if (pictureFile) fs.unlinkSync(pictureFile.path);
            return res.status(400).json({ message: validationError });
        }

        // Handle picture upload for students
        let pictureUrl = null;
        if (userType === 'student' && pictureFile) {
            const fileExt = path.extname(pictureFile.originalname);
            const fileName = `students/${userData.student_id}-${Date.now()}${fileExt}`;
            
            const { error: uploadError } = await supabase.storage
                .from('school-media')
                .upload(fileName, fs.readFileSync(pictureFile.path), {
                    contentType: pictureFile.mimetype,
                    upsert: false
                });

            fs.unlinkSync(pictureFile.path);
            if (uploadError) throw uploadError;

            pictureUrl = `${process.env.SUPABASE_URL}/storage/v1/object/public/school-media/${fileName}`;
        }

        // Hash password
        userData.password = await hashPassword(userData.password);

        // Prepare user record
        const userRecord = {
            role: userType,
            password: userData.password,
            full_name: userData.full_name,
            gender: userData.gender,
            is_active: true,
            ...(userType === 'admin' && { email: userData.email }),
            ...(userType === 'teacher' && { 
                email: userData.email,
                class: userData.class 
            }),
            ...(userType === 'student' && { 
                student_id: userData.student_id,
                class: userData.class,
                profile_picture: pictureUrl
            })
        };

        // Create user in database
        const { data: user, error: userError } = await supabase
            .from('users')
            .insert([userRecord])
            .select()
            .single();

        if (userError) {
            // Clean up uploaded picture if there was an error
            if (pictureUrl) {
                const fileName = pictureUrl.split('/').pop();
                await supabase.storage.from('school-media').remove([`students/${fileName}`]);
            }
            throw userError;
        }

        // Generate token (optional - might not need for admin-created users)
        const token = jwt.sign({ id: user.id, role: userType }, JWT_SECRET, { expiresIn: '8h' });

        // Return appropriate response
        const response = {
            message: `${userType} created successfully`,
            user: {
                id: user.id,
                ...(userType === 'admin' && { email: user.email }),
                ...(userType === 'teacher' && { email: user.email }),
                ...(userType === 'student' && { student_id: user.student_id }),
                full_name: user.full_name,
                role: userType,
                ...(userType === 'student' && { profile_picture: user.profile_picture })
            }
        };

        if (userType !== 'admin') {
            response.token = token; // Only return token for non-admin users
        }

        res.status(201).json(response);

    } catch (error) {
        console.error('Admin create user error:', error);
        res.status(500).json({ 
            message: 'Failed to create user',
            error: error.message 
        });
    }
});

// [16] ADMIN GET ALL USERS
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only admins can access
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        // Determine if inactive users should be included
        const includeInactive = req.query.includeInactive === 'true';

        let query = supabase
            .from('users')
            .select('id, email, student_id, full_name, role, class, gender, is_active, profile_picture, created_at');
        
        if (!includeInactive) {
            query = query.eq('is_active', true); // Only fetch active users by default
        }

        const { data: users, error } = await query.order('created_at', { ascending: false }); // Order by creation date

        if (error) throw error;

        res.json({
            message: 'Users fetched successfully',
            users: users || []
        });

    } catch (error) {
        console.error('Admin get all users error:', error);
        res.status(500).json({
            message: 'Failed to fetch users',
            error: error.message
        });
    }
});

// [17] ADMIN DELETE USER
app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only admins can access
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        const userIdToDelete = req.params.id;

        // Prevent admin from deleting themselves
        if (req.user.id === userIdToDelete) {
            return res.status(400).json({ message: 'Admins cannot delete their own account through this endpoint.' });
        }

        // First, get the user to be deleted to check their role and profile picture
        const { data: userToDelete, error: fetchError } = await supabase
            .from('users')
            .select('role, profile_picture')
            .eq('id', userIdToDelete)
            .single();

        if (fetchError || !userToDelete) {
            return res.status(404).json({ message: 'User not found' });
        }

        // If the user is a student and has a profile picture, delete it from storage
        if (userToDelete.role === 'student' && userToDelete.profile_picture) {
            try {
                // Extract the path within the bucket (e.g., 'students/filename.png')
                const urlParts = userToDelete.profile_picture.split('/public/school-media/');
                if (urlParts.length > 1) {
                    const filePathInStorage = urlParts[1];
                    const { error: deletePictureError } = await supabase.storage
                        .from('school-media')
                        .remove([filePathInStorage]);

                    if (deletePictureError) {
                        console.warn(`Warning: Failed to delete profile picture for user ${userIdToDelete}:`, deletePictureError.message);
                        // Do not throw here, allow user deletion to proceed even if picture deletion fails
                    }
                }
            } catch (pictureCleanupError) {
                console.error(`Error during profile picture cleanup for user ${userIdToDelete}:`, pictureCleanupError);
                // Continue with user deletion
            }
        }

        // Now, delete the user from the database
        const { error: deleteError } = await supabase
            .from('users')
            .delete()
            .eq('id', userIdToDelete);

        if (deleteError) throw deleteError;

        res.status(200).json({ message: 'User deleted successfully' });

    } catch (error) {
        console.error('Admin delete user error:', error);
        res.status(500).json({
            message: 'Failed to delete user',
            error: error.message
        });
    }
});

// [18] ADMIN GET ALL RESULTS
app.get('/api/admin/results', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only admins can access
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        // Fetch all results with related student, subject, and session info
        const { data: results, error } = await supabase
            .from('results')
            .select(`
                id,
                pt1, pt2, pt3, avg_pt, exam, total_score, grade, remark, is_approved, created_at,
                students:student_id(id, student_id, full_name, class),
                subjects:subject_id(id, name),
                sessions:session_id(id, name)
            `)
            .order('created_at', { ascending: false }); // Order by creation date

        if (error) throw error;

        // Transform data for easier consumption in frontend if needed
        const formattedResults = results.map(r => ({
            id: r.id,
            student_id: r.students.student_id,
            student_name: r.students.full_name,
            student_class: r.students.class,
            subject_name: r.subjects.name,
            session_name: r.sessions.name,
            term: r.term, // Added term as it's useful for displaying results
            pt1: r.pt1,
            pt2: r.pt2,
            pt3: r.pt3,
            avg_pt: r.avg_pt,
            exam: r.exam,
            total_score: r.total_score,
            grade: r.grade,
            remark: r.remark,
            is_approved: r.is_approved,
            created_at: r.created_at
        }));

        res.json({
            message: 'Results fetched successfully',
            results: formattedResults || []
        });

    } catch (error) {
        console.error('Admin get all results error:', error);
        res.status(500).json({
            message: 'Failed to fetch results',
            error: error.message
        });
    }
});

// [19] ADMIN APPROVE RESULT
app.put('/api/admin/results/:id/approve', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only admins can access
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        const resultId = req.params.id;

        // Update the is_approved status for the specific result
        const { data, error } = await supabase
            .from('results')
            .update({ is_approved: true })
            .eq('id', resultId)
            .select() // Select updated row to confirm
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ message: 'Result not found or already approved' });

        res.status(200).json({
            message: 'Result approved successfully',
            result: data
        });

    } catch (error) {
        console.error('Admin approve result error:', error);
        res.status(500).json({
            message: 'Failed to approve result',
            error: error.message
        });
    }
});

// [20] ADMIN PROMOTE STUDENTS
app.post('/api/admin/promote-students', authenticateToken, async (req, res) => {
    try {
        // Authorization check - only admins can access
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        let promotedCount = 0;
        let graduatedCount = 0;
        let skippedCount = 0;
        const errors = [];

        // Fetch all active students
        const { data: students, error: fetchStudentsError } = await supabase
            .from('users')
            .select('id, full_name, class, student_id, is_active')
            .eq('role', 'student')
            .eq('is_active', true); // Only promote active students

        if (fetchStudentsError) throw fetchStudentsError;

        if (!students || students.length === 0) {
            return res.status(200).json({ message: 'No active students found to promote.', promotedCount: 0, graduatedCount: 0 });
        }

        const promotionPromises = students.map(async (student) => {
            const currentClass = student.class;
            const nextClass = PROMOTION_MAP[currentClass];

            if (nextClass) {
                if (nextClass === 'GRADUATED') {
                    // Update to 'GRADUATED' and set is_active to false
                    const { error: updateError } = await supabase
                        .from('users')
                        .update({ class: 'GRADUATED', is_active: false })
                        .eq('id', student.id);
                    
                    if (updateError) {
                        errors.push(`Failed to graduate student ${student.full_name} (${student.student_id}): ${updateError.message}`);
                        return false; // Indicate failure for this student
                    }
                    graduatedCount++;
                    return true; // Indicate success
                } else {
                    // Update to next class
                    const { error: updateError } = await supabase
                        .from('users')
                        .update({ class: nextClass })
                        .eq('id', student.id);
                    
                    if (updateError) {
                        errors.push(`Failed to promote student ${student.full_name} (${student.student_id}): ${updateError.message}`);
                        return false; // Indicate failure
                    }
                    promotedCount++;
                    return true; // Indicate success
                }
            } else {
                skippedCount++;
                errors.push(`Student ${student.full_name} (${student.student_id}) in class "${currentClass}" has no defined next class in PROMOTION_MAP.`);
                return false; // Indicate skipped
            }
        });

        // Wait for all promotion updates to complete
        await Promise.all(promotionPromises);

        res.status(200).json({
            message: 'Student promotion process completed.',
            promotedCount,
            graduatedCount,
            skippedCount,
            details: errors.length > 0 ? 'Some students could not be processed: ' + errors.join('; ') : 'All eligible students processed successfully.'
        });

    } catch (error) {
        console.error('Admin promote students error:', error);
        res.status(500).json({
            message: 'Failed to promote students',
            error: error.message
        });
    }
});

// [21] ADMIN EXPORT RESULTS
app.get('/api/admin/export-results/:class/:term/:session', authenticateToken, async (req, res) => {
    console.log('--- EXPORT RESULTS ROUTE HIT ---'); // ADDED LOG
    console.log('Request URL:', req.originalUrl); // ADDED LOG
    console.log('Params:', req.params); // ADDED LOG

    try {
        if (req.user.role !== 'admin') {
            console.log('Authorization Failed: User is not admin.'); // ADDED LOG
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        const { class: className, term, session } = req.params;
        console.log(`Export request for Class: ${className}, Term: ${term}, Session: ${session}`); // ADDED LOG

        const schoolInfoResponse = await _fetchApi(`http://localhost:${PORT}/api/school-info`);
        if (!schoolInfoResponse.ok) {
            console.error(`Failed to fetch school information: ${schoolInfoResponse.status} ${schoolInfoResponse.statusText}`); // ADDED LOG
            throw new Error(`Failed to fetch school information: ${schoolInfoResponse.status} ${schoolInfoResponse.statusText}`);
        }
        const schoolInfo = await schoolInfoResponse.json();

        const { data: sessionData, error: sessionError } = await supabase
            .from('sessions')
            .select('id')
            .eq('name', session)
            .single();

        if (sessionError || !sessionData) {
            console.log(`Session not found in DB for name "${session}":`, sessionError ? sessionError.message : 'No data'); // ADDED LOG
            return res.status(404).json({ message: 'Session not found for export' });
        }
        const sessionId = sessionData.id;
        console.log(`Found session ID: ${sessionId} for session name "${session}"`); // ADDED LOG

        const { data: results, error: resultsError } = await supabase
            .from('results')
            .select(`
                id,
                pt1, pt2, pt3, avg_pt, exam, total_score, grade, remark, created_at,
                students:student_id!inner(id, student_id, full_name, gender, profile_picture, class),
                subjects:subject_id(name)
            `)
            .eq('is_approved', true) 
            .eq('term', term)
            .eq('session_id', sessionId)
            .eq('students.class', className) 
            .order('students(full_name)', { ascending: true }) 
            .order('subjects(name)', { ascending: true }); 

        if (resultsError) {
            console.error('Error fetching results for export from Supabase:', resultsError.message); // ADDED LOG
            throw new Error('Failed to fetch results for export');
        }

        if (!results || results.length === 0) {
            console.log('No approved results found in DB for query parameters:', { className, term, sessionId }); // ADDED LOG
            return res.status(404).json({ message: 'No approved results found for students in this class, term, and session.' });
        }
        console.log(`Fetched ${results.length} approved results from Supabase.`); // ADDED LOG


        // Group results by student
        const studentsResultsMap = {};
        results.forEach(result => {
            const studentId = result.students.id;
            if (!studentsResultsMap[studentId]) {
                studentsResultsMap[studentId] = {
                    ...result.students,
                    academicResults: [],
                    psychomotor: {}
                };
            }
            studentsResultsMap[studentId].academicResults.push({
                subject_name: result.subjects.name,
                pt1: result.pt1,
                pt2: result.pt2,
                pt3: result.pt3,
                avg_pt: result.avg_pt,
                exam: result.exam,
                total_score: result.total_score,
                grade: result.grade,
                remark: result.remark
            });
        });
        
        const studentsToExport = Object.values(studentsResultsMap);
        console.log(`Prepared data for ${studentsToExport.length} students.`); // ADDED LOG

        if (studentsToExport.length === 0) {
            console.warn('After grouping, still no students to export. This should not happen if previous query returned results.'); // ADDED WARNING
            return res.status(404).json({ message: 'No approved results found for students in this class.' });
        }

        // Fetch psychomotor skills for all relevant students
        const studentIds = studentsToExport.map(s => s.id); 
        const { data: psychomotorSkills, error: psychomotorError } = await supabase
            .from('psychomotor')
            .select('*')
            .in('student_id', studentIds)
            .eq('term', term)
            .eq('session_id', sessionId);

        if (psychomotorError) {
            console.warn('Error fetching psychomotor skills:', psychomotorError.message); 
        } else {
            console.log(`Fetched ${psychomotorSkills ? psychomotorSkills.length : 0} psychomotor records.`); // ADDED LOG
            psychomotorSkills.forEach(skill => {
                if (studentsResultsMap[skill.student_id]) {
                    studentsResultsMap[skill.student_id].psychomotor = skill;
                }
            });
        }

        // Create a new PDFDocument (PDF generation logic remains the same)
        const pdfDoc = await PDFDocument.create();
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

        let logoImage = null;
        if (schoolInfo.logo_url) {
            try {
                const logoResponse = await _fetchApi(schoolInfo.logo_url);
                if (!logoResponse.ok) {
                    console.warn(`Failed to fetch logo: ${logoResponse.status} ${logoResponse.statusText}`);
                    logoImage = null;
                } else {
                    const logoBytes = await logoResponse.arrayBuffer();
                    const imageType = schoolInfo.logo_url.endsWith('.png') ? 'image/png' : 'image/jpeg';
                    logoImage = imageType === 'image/png'
                        ? await pdfDoc.embedPng(logoBytes)
                        : await pdfDoc.embedJpg(logoBytes);
                    console.log('Logo embedded successfully.'); // ADDED LOG
                }
            } catch (logoErr) {
                console.warn('Could not embed logo:', logoErr.message);
                logoImage = null; 
            }
        }
        
        const pageSize = [595, 842]; 
        const margin = 30;
        const columnWidths = [120, 40, 40, 40, 50, 40, 50, 40, 70]; 
        const tableHeaderHeight = 20;
        const rowHeight = 15;
        const psychomotorRowHeight = 15;
        const psychomotorColumnWidths = [100, 50]; 

        let yPosition;
        let currentPage;

        const addPageHeader = () => {
            currentPage = pdfDoc.addPage(pageSize);
            yPosition = pageSize[1] - margin;

            // --- Watermark ---
            if (logoImage) {
                const logoAspectRatio = logoImage.width / logoImage.height;
                const pageContentWidth = pageSize[0] - (2 * margin);
                const pageContentHeight = pageSize[1] - (2 * margin);
                let watermarkWidth = pageContentWidth * 0.7; 
                let watermarkHeight = watermarkWidth / logoAspectRatio;
                if (watermarkHeight > pageContentHeight * 0.7) {
                    watermarkHeight = pageContentHeight * 0.7;
                    watermarkWidth = watermarkHeight * logoAspectRatio;
                }
                const watermarkX = (pageSize[0] - watermarkWidth) / 2;
                const watermarkY = (pageSize[1] - watermarkHeight) / 2;
                currentPage.drawImage(logoImage, {
                    x: watermarkX,
                    y: watermarkY,
                    width: watermarkWidth,
                    height: watermarkHeight,
                    opacity: 0.1, 
                });
            }

            // --- Regular Header Content (School Info) ---
            currentPage.drawText(schoolInfo.name.toUpperCase(), {
                x: margin, y: pageSize[1] - margin, font: boldFont, size: 16, color: rgb(0.1, 0.1, 0.4),
            });
            currentPage.drawText(schoolInfo.motto, {
                x: margin, y: pageSize[1] - margin - 15, font: font, size: 10, color: rgb(0.3, 0.3, 0.3),
            });
            currentPage.drawText(`Address: ${schoolInfo.address}`, {
                x: margin, y: pageSize[1] - margin - 35, font: font, size: 8, color: rgb(0.2, 0.2, 0.2),
            });
            currentPage.drawText(`Phone: ${schoolInfo.phone} | Email: ${schoolInfo.email}`, {
                x: margin, y: pageSize[1] - margin - 45, font: font, size: 8, color: rgb(0.2, 0.2, 0.2),
            });

            yPosition = pageSize[1] - margin - 70; 
        };

        addPageHeader();

        currentPage.drawText(`${className} Class Results`, {
            x: margin, y: yPosition, font: boldFont, size: 14, color: rgb(0, 0, 0),
        });
        currentPage.drawText(`${term} Term, ${session} Session`, {
            x: margin, y: yPosition - 15, font: font, size: 10, color: rgb(0.5, 0.5, 0.5),
        });
        yPosition -= 40; 

        for (const student of studentsToExport) {
            const studentAcademicResults = student.academicResults;
            const studentPsychomotor = student.psychomotor;

            // Calculate overall performance for the student for the current term (same logic as in student results endpoint)
            const studentTotalObtainable = studentAcademicResults.length * 100;
            const studentTotalScored = studentAcademicResults.reduce((sum, r) => sum + r.total_score, 0);
            const studentPercentage = studentTotalObtainable > 0 ? (studentTotalScored / studentTotalObtainable) * 100 : 0;

            let teacherComment = '';
            if (studentPercentage >= 70) teacherComment = 'Brilliant student with good potentials, never relent';
            else if (studentPercentage >= 60) teacherComment = 'This is not yet your limit, you can do more';
            else if (studentPercentage >= 50) teacherComment = 'Good, but there is a need for serious improvement and seriousness';
            else if (studentPercentage >= 40) teacherComment = 'Try harder, you have the potentials';
            else teacherComment = 'Needs urgent attention and improvement';

            let headTeacherComment = '';
            if (studentPercentage >= 80) headTeacherComment = 'Outstanding performance! Keep soaring higher. - Mr Olusegun';
            else if (studentPercentage >= 70) headTeacherComment = 'Excellent result. Maintain this standard. - Mr Olusegun';
            else if (studentPercentage >= 60) headTeacherComment = 'Excellent performance. Aim for excellence. - Mr Olusegun';
            else if (studentPercentage >= 50) headTeacherComment = 'Satisfactory result. More effort required. - Mr Olusegun';
            else if (studentPercentage >= 40) headTeacherComment = 'Fair performance. Significant improvement needed. - Mr Olusegun';
            else headTeacherComment = 'Unsatisfactory performance. Immediate remediation required. - Mr Olusegun';

            const estimatedStudentBlockHeight = 40 + (studentAcademicResults.length * rowHeight) + 30 + (Object.keys(studentPsychomotor).length > 0 ? (7 * psychomotorRowHeight) + 10 : 0) + 60;

            if (yPosition < margin + estimatedStudentBlockHeight) {
                addPageHeader(); 
            }

            currentPage.drawText(`Student: ${student.full_name} (ID: ${student.student_id})`, {
                x: margin, y: yPosition - 20, font: boldFont, size: 12, color: rgb(0.1, 0.1, 0.5),
            });
            yPosition -= 40;

            let x = margin;
            currentPage.drawRectangle({
                x: x, y: yPosition - tableHeaderHeight, width: columnWidths.reduce((sum, w) => sum + w, 0), height: tableHeaderHeight, color: rgb(0.9, 0.9, 0.95),
            });
            const academicHeaders = ['Subject', 'PT1', 'PT2', 'PT3', 'Avg PT', 'Exam', 'Total', 'Grade', 'Remark'];
            academicHeaders.forEach((header, index) => {
                currentPage.drawText(header, {
                    x: x + 5, y: yPosition - tableHeaderHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0),
                });
                x += columnWidths[index];
            });
            yPosition -= tableHeaderHeight;

            for (const res of studentAcademicResults) {
                if (yPosition < margin + rowHeight) {
                    addPageHeader(); 
                    x = margin;
                    currentPage.drawRectangle({
                        x: x, y: yPosition - tableHeaderHeight, width: columnWidths.reduce((sum, w) => sum + w, 0), height: tableHeaderHeight, color: rgb(0.9, 0.9, 0.95),
                    });
                    academicHeaders.forEach((header, index) => {
                        currentPage.drawText(header, {
                            x: x + 5, y: yPosition - tableHeaderHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0),
                        });
                        x += columnWidths[index];
                    });
                    yPosition -= tableHeaderHeight;
                }

                x = margin;
                const rowValues = [
                    res.subject_name, res.pt1, res.pt2, res.pt3, res.avg_pt, res.exam, res.total_score, res.grade, res.remark
                ];
                rowValues.forEach((val, index) => {
                    currentPage.drawText(String(val), {
                        x: x + 5, y: yPosition - rowHeight + 5, font: font, size: 8, color: rgb(0, 0, 0),
                    });
                    x += columnWidths[index];
                });
                yPosition -= rowHeight;
            }
            yPosition -= 10; 

            if (Object.keys(studentPsychomotor).length > 0) {
                if (yPosition < margin + (psychomotorRowHeight * 4)) { 
                    addPageHeader();
                }
                currentPage.drawText('Psychomotor Skills:', {
                    x: margin, y: yPosition - 10, font: boldFont, size: 10, color: rgb(0.2, 0.2, 0.6),
                });
                yPosition -= 25;

                const psychomotorHeaders = ['Attribute', 'Score'];
                const psychomotorAttributes = [
                    { name: 'Attendance', score: studentPsychomotor.attendance },
                    { name: 'Punctuality', score: studentPsychomotor.punctuality },
                    { name: 'Neatness', score: studentPsychomotor.neatness },
                    { name: 'Honesty', score: studentPsychomotor.honesty },
                    { name: 'Responsibility', score: studentPsychomotor.responsibility },
                    { name: 'Creativity', score: studentPsychomotor.creativity },
                    { name: 'Sports', score: studentPsychomotor.sports }
                ];
                
                x = margin;
                currentPage.drawRectangle({
                    x: x, y: yPosition - tableHeaderHeight, width: psychomotorColumnWidths[0] + psychomotorColumnWidths[1], height: tableHeaderHeight, color: rgb(0.9, 0.95, 0.9),
                });
                currentPage.drawText(psychomotorHeaders[0], {
                    x: x + 5, y: yPosition - tableHeaderHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0),
                });
                x += psychomotorColumnWidths[0];
                currentPage.drawText(psychomotorHeaders[1], {
                    x: x + 5, y: yPosition - tableHeaderHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0),
                });
                yPosition -= tableHeaderHeight;

                for (const attr of psychomotorAttributes) {
                    if (yPosition < margin + psychomotorRowHeight) {
                        addPageHeader();
                        x = margin;
                        currentPage.drawRectangle({
                            x: x, y: yPosition - tableHeaderHeight, width: psychomotorColumnWidths[0] + psychomotorColumnWidths[1], height: tableHeaderHeight, color: rgb(0.9, 0.95, 0.9),
                        });
                        currentPage.drawText(psychomotorHeaders[0], {
                            x: x + 5, y: yPosition - tableHeaderHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0),
                        });
                        x += psychomotorColumnWidths[0];
                        currentPage.drawText(psychomotorHeaders[1], {
                            x: x + 5, y: yPosition - psychomotorRowHeight + 5, font: boldFont, size: 8, color: rgb(0, 0, 0),
                        });
                        yPosition -= tableHeaderHeight;
                    }
                    
                    x = margin;
                    currentPage.drawText(attr.name, {
                        x: x + 5, y: yPosition - psychomotorRowHeight + 5, font: font, size: 8, color: rgb(0, 0, 0),
                    });
                    x += psychomotorColumnWidths[0];
                    currentPage.drawText(String(attr.score), {
                        x: x + 5, y: yPosition - psychomotorRowHeight + 5, font: font, size: 8, color: rgb(0, 0, 0),
                    });
                    yPosition -= psychomotorRowHeight;
                }
                yPosition -= 10;
            }

            // Comments
            if (yPosition < margin + 60) { // Check space for comments
                addPageHeader();
            }
            currentPage.drawText(`Teacher's Comment: ${teacherComment}`, {
                x: margin,
                y: yPosition - 10,
                font: font,
                size: 9,
                color: rgb(0.2, 0.2, 0.2),
            });
            currentPage.drawText(`Head Teacher's Comment: ${headTeacherComment}`, {
                x: margin,
                y: yPosition - 25,
                font: font,
                size: 9,
                color: rgb(0.2, 0.2, 0.2),
            });
            yPosition -= 50; // Space after comments
        }


        // Finalize PDF
        const pdfBytes = await pdfDoc.save();

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${className}_${term}_${session}_results.pdf"`);
        res.send(Buffer.from(pdfBytes));

    } catch (error) {
        console.error('Export results error:', error);
        res.status(500).json({
            message: 'Failed to export results',
            error: error.message
        });
    }
});

// [22] ADMIN SEND NOTIFICATION TO STUDENTS
app.post('/api/admin/send-notification', authenticateToken, async (req, res) => {
    console.log('--- SEND NOTIFICATION ROUTE HIT ---');
    console.log('Request Body:', req.body);
    console.log('User from token (sender):', req.user);

    try {
        if (req.user.role !== 'admin') {
            console.log('Authorization Failed: User is not admin.');
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        const { recipientType, recipientClass, recipientStudentId, subject, messageBody } = req.body;
        const senderId = req.user.id; // The ID of the admin sending the notification

        // Basic validation
        if (!subject || !messageBody) {
            return res.status(400).json({ message: 'Subject and message body are required.' });
        }

        let targetStudentUserIds = [];
        let classForNotification = null; // Will store class if specified or derived

        // Determine target students based on recipientType
        if (recipientType === 'all') {
            const { data: students, error } = await supabase
                .from('users')
                .select('id, class') // Also fetch class to store in notification table
                .eq('role', 'student')
                .eq('is_active', true);

            if (error) throw error;
            targetStudentUserIds = students.map(s => s.id);
            // Since it's 'all', we don't have a specific class to store, so classForNotification remains null.
            // Or we could store a generic 'All Classes' if that makes sense for your UI.
        } else if (recipientType === 'class') {
            if (!recipientClass) {
                return res.status(400).json({ message: 'Recipient class is required for class-specific notifications.' });
            }
            const { data: students, error } = await supabase
                .from('users')
                .select('id')
                .eq('role', 'student')
                .eq('class', recipientClass)
                .eq('is_active', true);

            if (error) throw error;
            targetStudentUserIds = students.map(s => s.id);
            classForNotification = recipientClass; // Store the class name
        } else if (recipientType === 'student') {
            if (!recipientStudentId) {
                return res.status(400).json({ message: 'Recipient student ID is required for student-specific notifications.' });
            }
            const { data: student, error } = await supabase
                .from('users')
                .select('id, class') // Fetch class to store in notification table
                .eq('role', 'student')
                .eq('student_id', recipientStudentId)
                .eq('is_active', true)
                .single();

            if (error || !student) {
                return res.status(404).json({ message: `Student with ID "${recipientStudentId}" not found or is inactive.` });
            }
            targetStudentUserIds.push(student.id);
            classForNotification = student.class; // Store the student's class
        } else {
            return res.status(400).json({ message: 'Invalid recipient type.' });
        }

        if (targetStudentUserIds.length === 0) {
            return res.status(404).json({ message: 'No active students found for the specified recipient type/class/ID.' });
        }

        // Prepare notification records for bulk insert
        const notificationsToInsert = targetStudentUserIds.map(studentId => ({
            recipient_id: studentId,
            recipient_class: classForNotification, // Will be null for 'all', or the class name otherwise
            sender_id: senderId,
            subject: subject,
            message_body: messageBody,
            is_read: false // Default to unread
        }));

        const { error: insertError } = await supabase
            .from('notifications')
            .insert(notificationsToInsert);

        if (insertError) {
            console.error('Error inserting notifications:', insertError);
            throw new Error('Failed to save notifications to database.');
        }

        res.status(200).json({ message: `Notification sent successfully to ${targetStudentUserIds.length} student(s).` });

    } catch (error) {
        console.error('Send notification error:', error);
        res.status(500).json({
            message: 'Failed to send notification',
            error: error.message
        });
    }
});

// [23] ADMIN GET PORTAL ANALYSIS DATA
app.get('/api/admin/analysis', authenticateToken, async (req, res) => {
    console.log('--- DATA ANALYSIS ROUTE HIT ---');
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Unauthorized - Admin access required' });
        }

        // 1. User Counts
        const { count: totalUsers, error: usersCountError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });
        if (usersCountError) throw usersCountError;

        const { count: totalAdmins, error: adminsCountError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('role', 'admin');
        if (adminsCountError) throw adminsCountError;

        const { count: totalTeachers, error: teachersCountError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('role', 'teacher');
        if (teachersCountError) throw teachersCountError;

        const { count: totalStudents, error: studentsCountError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('role', 'student');
        if (studentsCountError) throw studentsCountError;

        const { count: activeStudents, error: activeStudentsCountError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('role', 'student')
            .eq('is_active', true);
        if (activeStudentsCountError) throw activeStudentsCountError;

        const { count: inactiveStudents, error: inactiveStudentsCountError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('role', 'student')
            .eq('is_active', false);
        if (inactiveStudentsCountError) throw inactiveStudentsCountError;


        // 2. Results Statistics
        const { count: totalResults, error: resultsCountError } = await supabase
            .from('results')
            .select('*', { count: 'exact', head: true });
        if (resultsCountError) throw resultsCountError;

        const { count: approvedResults, error: approvedResultsCountError } = await supabase
            .from('results')
            .select('*', { count: 'exact', head: true })
            .eq('is_approved', true);
        if (approvedResultsCountError) throw approvedResultsCountError;

        const { count: pendingResults, error: pendingResultsCountError } = await supabase
            .from('results')
            .select('*', { count: 'exact', head: true })
            .eq('is_approved', false);
        if (pendingResultsCountError) throw pendingResultsCountError;

        const { data: allApprovedScores, error: scoresError } = await supabase
            .from('results')
            .select('total_score')
            .eq('is_approved', true);
        if (scoresError) throw scoresError;

        const averageTotalScore = (allApprovedScores && allApprovedScores.length > 0)
            ? (allApprovedScores.reduce((sum, r) => sum + r.total_score, 0) / allApprovedScores.length).toFixed(2)
            : 'N/A';

        // 3. Notification Statistics
        const { count: totalNotifications, error: notificationsCountError } = await supabase
            .from('notifications')
            .select('*', { count: 'exact', head: true });
        if (notificationsCountError) throw notificationsCountError;

        const { count: readNotifications, error: readNotificationsCountError } = await supabase
            .from('notifications')
            .select('*', { count: 'exact', head: true })
            .eq('is_read', true);
        if (readNotificationsCountError) throw readNotificationsCountError;

        const { count: unreadNotifications, error: unreadNotificationsCountError } = await supabase
            .from('notifications')
            .select('*', { count: 'exact', head: true })
            .eq('is_read', false);
        if (unreadNotificationsCountError) throw unreadNotificationsCountError;


        res.status(200).json({
            message: 'Portal analysis data fetched successfully.',
            analysis: {
                users: {
                    total: totalUsers,
                    admins: totalAdmins,
                    teachers: totalTeachers,
                    students: totalStudents,
                    activeStudents: activeStudents,
                    inactiveStudents: inactiveStudents
                },
                results: {
                    total: totalResults,
                    approved: approvedResults,
                    pending: pendingResults,
                    averageTotalScore: parseFloat(averageTotalScore)
                },
                notifications: {
                    total: totalNotifications,
                    read: readNotifications,
                    unread: unreadNotifications
                }
            }
        });

    } catch (error) {
        console.error('Data analysis error:', error);
        res.status(500).json({
            message: 'Failed to fetch analysis data',
            error: error.message
        });
    }
});


// Start Server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access at http://localhost:${PORT}`);
});
