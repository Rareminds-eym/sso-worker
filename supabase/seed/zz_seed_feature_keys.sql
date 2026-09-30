-- Seeds public.feature_keys with the full, current admin-dashboard nav
-- catalog for skillpassport's three admin roles (college_admin, school_admin,
-- university_admin), sourced 1:1 from
-- skillpassport/src/features/admin/ui/Sidebar.tsx.
--
-- Excludes nav items that are statically `disabled: true` in the sidebar
-- today (not built yet — unrelated to plan-gating): Attendance Policies,
-- Performance, Graduation & Alumni, Coverage Tracker, Academic Calendar,
-- Grading & Assessments, Transcripts, Skill Development (all college_admin;
-- school_admin and university_admin have no disabled items).
--
-- Idempotent: safe to re-run. Looks up the skillpassport product by code
-- rather than a hardcoded id, since that id can differ per environment.
--
-- Date: 2026-09-25
DO $$
DECLARE
  v_product_id uuid;
BEGIN
  SELECT id INTO v_product_id FROM public.products WHERE code = 'skillpassport';

  IF v_product_id IS NULL THEN
    RAISE EXCEPTION 'seed_feature_keys: no products row with code=skillpassport — seed products first';
  END IF;

  INSERT INTO public.feature_keys (product_id, key, role, nav_group, nav_label, nav_path, display_order)
  VALUES
    -- ── college_admin — Learners ──────────────────────────────────────
    (v_product_id, 'admissions_data', 'college_admin', 'Learners', 'Admissions & Data', '/college-admin/learners/data-management', 10),
    (v_product_id, 'enrolled_learners', 'college_admin', 'Learners', 'Enrolled Learners', '/college-admin/learners/enrolled', 20),
    (v_product_id, 'learner_attendance', 'college_admin', 'Learners', 'Attendance', '/college-admin/learners/attendance', 30),
    (v_product_id, 'assessment_results', 'college_admin', 'Learners', 'Assessment Results', '/college-admin/learners/assessment-results', 40),
    (v_product_id, 'digital_portfolio', 'college_admin', 'Learners', 'Digital Portfolio', '/college-admin/learners/digital-portfolio', 50),
    (v_product_id, 'learner_verifications', 'college_admin', 'Learners', 'Verifications', '/college-admin/learners/verifications', 60),
    (v_product_id, 'learner_communication', 'college_admin', 'Learners', 'Communication', '/college-admin/learners/communication', 70),
    -- ── college_admin — Departments & Faculty ─────────────────────────
    (v_product_id, 'departments', 'college_admin', 'Departments & Faculty', 'Departments', '/college-admin/departments/management', 80),
    (v_product_id, 'faculty', 'college_admin', 'Departments & Faculty', 'Faculty', '/college-admin/departments/educators', 90),
    -- ── college_admin — Academics ──────────────────────────────────────
    (v_product_id, 'courses', 'college_admin', 'Academics', 'Courses', '/college-admin/academics/browse-courses', 100),
    (v_product_id, 'programs', 'college_admin', 'Academics', 'Programs', '/college-admin/academics/programs', 110),
    (v_product_id, 'program_sections', 'college_admin', 'Academics', 'Program & Sections', '/college-admin/academics/program-sections', 120),
    (v_product_id, 'course_mapping', 'college_admin', 'Academics', 'Course Mapping', '/college-admin/departments/mapping', 130),
    (v_product_id, 'curriculum_builder', 'college_admin', 'Academics', 'Curriculum Builder', '/college-admin/academics/curriculum', 140),
    (v_product_id, 'lesson_plans', 'college_admin', 'Academics', 'Lesson Plans', '/college-admin/academics/lesson-plans', 150),
    -- ── college_admin — Examinations ───────────────────────────────────
    (v_product_id, 'exam_management', 'college_admin', 'Examinations', 'Exam Management', '/college-admin/examinations', 160),
    -- ── college_admin — Placements & Skills ────────────────────────────
    (v_product_id, 'placement_status', 'college_admin', 'Placements & Skills', 'Placements', '/college-admin/placements', 170),
    (v_product_id, 'mentors', 'college_admin', 'Placements & Skills', 'Mentors', '/college-admin/mentors', 180),
    -- ── college_admin — Operations ──────────────────────────────────────
    (v_product_id, 'finance', 'college_admin', 'Operations', 'Finance', '/college-admin/finance', 190),
    (v_product_id, 'library', 'college_admin', 'Operations', 'Library', '/college-admin/library', 200),
    (v_product_id, 'events', 'college_admin', 'Operations', 'Events', '/college-admin/events', 210),
    (v_product_id, 'circulars', 'college_admin', 'Operations', 'Circulars', '/college-admin/circulars', 220),
    -- ── college_admin — Administration ──────────────────────────────────
    (v_product_id, 'user_management', 'college_admin', 'Administration', 'User Management', '/college-admin/users', 230),
    (v_product_id, 'reports_analytics', 'college_admin', 'Administration', 'Reports & Analytics', '/college-admin/reports', 240),
    (v_product_id, 'basic_analytics', 'college_admin', 'Administration', 'Course Analytics', '/college-admin/course-analytics', 250),

    -- ── school_admin — Learner Management ──────────────────────────────
    (v_product_id, 'admissions', 'school_admin', 'Learner Management', 'Admissions', '/school-admin/learners/admissions', 10),
    (v_product_id, 'digital_portfolio', 'school_admin', 'Learner Management', 'Digital Portfolio', '/school-admin/learners/digital-portfolio', 20),
    (v_product_id, 'class_management', 'school_admin', 'Learner Management', 'Class Management', '/school-admin/classes/management', 30),
    (v_product_id, 'attendance_reports', 'school_admin', 'Learner Management', 'Attendance & Reports', '/school-admin/learners/attendance-reports', 40),
    (v_product_id, 'assessment_results', 'school_admin', 'Learner Management', 'Assessment Results', '/school-admin/learners/assessment-results', 50),
    (v_product_id, 'learner_verifications', 'school_admin', 'Learner Management', 'Verifications', '/school-admin/learners/verifications', 60),
    -- ── school_admin — Teacher Management ──────────────────────────────
    (v_product_id, 'teachers', 'school_admin', 'Teacher Management', 'Teachers', '/school-admin/teachers/list', 70),
    (v_product_id, 'teacher_onboarding', 'school_admin', 'Teacher Management', 'Onboarding', '/school-admin/teachers/onboarding', 80),
    (v_product_id, 'teacher_timetable', 'school_admin', 'Teacher Management', 'Timetable', '/school-admin/teachers/timetable', 90),
    -- ── school_admin — Academic Management ─────────────────────────────
    (v_product_id, 'courses', 'school_admin', 'Academic Management', 'Courses', '/school-admin/academics/browse-courses', 100),
    (v_product_id, 'curriculum_builder', 'school_admin', 'Academic Management', 'Curriculum Builder', '/school-admin/academics/curriculum', 110),
    (v_product_id, 'lesson_plans', 'school_admin', 'Academic Management', 'Lesson Plans', '/school-admin/academics/lesson-plans', 120),
    (v_product_id, 'exams_assessments', 'school_admin', 'Academic Management', 'Exams & Assessments', '/school-admin/academics/exams', 130),
    -- ── school_admin — Parent & Communication ──────────────────────────
    (v_product_id, 'parent_portal', 'school_admin', 'Parent & Communication', 'Parent Portal', '/school-admin/communication/parents', 140),
    (v_product_id, 'message_center', 'school_admin', 'Parent & Communication', 'Message Center', '/school-admin/communication/messages', 150),
    (v_product_id, 'parent_communication', 'school_admin', 'Parent & Communication', 'Parent Communication', '/school-admin/communication/circulars', 160),
    (v_product_id, 'learner_communication', 'school_admin', 'Parent & Communication', 'Learner Communication', '/school-admin/communication/messages-learner', 170),
    -- ── school_admin — Finance & Infrastructure ────────────────────────
    (v_product_id, 'fee_setup_payments', 'school_admin', 'Finance & Infrastructure', 'Fee Setup & Payments', '/school-admin/finance/fees', 180),
    (v_product_id, 'library_assets', 'school_admin', 'Finance & Infrastructure', 'Library & Assets', '/school-admin/infrastructure/library', 190),
    (v_product_id, 'maintenance', 'school_admin', 'Finance & Infrastructure', 'Maintenance', '/school-admin/infrastructure/maintenance', 200),
    -- ── school_admin — Skill & Co-Curricular ───────────────────────────
    (v_product_id, 'clubs_competitions', 'school_admin', 'Skill & Co-Curricular', 'Clubs & Competitions', '/school-admin/skills/clubs', 210),
    (v_product_id, 'competition_certificates', 'school_admin', 'Skill & Co-Curricular', 'Competition Certificates', '/school-admin/skills/badges', 220),
    (v_product_id, 'skills_reports', 'school_admin', 'Skill & Co-Curricular', 'Reports', '/school-admin/skills/reports', 230),
    (v_product_id, 'basic_analytics', 'school_admin', 'Skill & Co-Curricular', 'Course Analytics', '/school-admin/course-analytics', 240),

    -- ── university_admin — Affiliated College Management ───────────────
    (v_product_id, 'college_registration', 'university_admin', 'Affiliated College Management', 'College Registration', '/university-admin/colleges/registration', 10),
    (v_product_id, 'program_allocation', 'university_admin', 'Affiliated College Management', 'Program Allocation', '/university-admin/colleges/programs', 20),
    (v_product_id, 'performance_monitoring', 'university_admin', 'Affiliated College Management', 'Performance Monitoring', '/university-admin/colleges/performance', 30),
    -- ── university_admin — Course & Curriculum Management ──────────────
    (v_product_id, 'courses', 'university_admin', 'Course & Curriculum Management', 'Courses', '/university-admin/browse-courses', 40),
    (v_product_id, 'syllabus_approval', 'university_admin', 'Course & Curriculum Management', 'Syllabus Approval', '/university-admin/courses/syllabus', 50),
    (v_product_id, 'course_updates', 'university_admin', 'Course & Curriculum Management', 'Course Updates', '/university-admin/courses/updates', 60),
    (v_product_id, 'content_repository', 'university_admin', 'Course & Curriculum Management', 'Content Repository', '/university-admin/courses/content', 70),
    -- ── university_admin — Faculty & Trainer Management ────────────────
    (v_product_id, 'faculty_empanelment', 'university_admin', 'Faculty & Trainer Management', 'Empanelment & Assignment', '/university-admin/faculty/empanelment', 80),
    (v_product_id, 'faculty_feedback_certification', 'university_admin', 'Faculty & Trainer Management', 'Feedback & Certification', '/university-admin/faculty/feedback', 90),
    -- ── university_admin — Learner Records ──────────────────────────────
    (v_product_id, 'enrollment_profiles', 'university_admin', 'Learner Records', 'Enrollment & Profiles', '/university-admin/learners/enrollments', 100),
    (v_product_id, 'digital_portfolios', 'university_admin', 'Learner Records', 'Digital Portfolios', '/university-admin/learners/digital-portfolios', 110),
    (v_product_id, 'assessment_results', 'university_admin', 'Learner Records', 'Assessment Results', '/university-admin/learners/assessment-results', 120),
    (v_product_id, 'continuous_assessment', 'university_admin', 'Learner Records', 'Continuous Assessment', '/university-admin/learners/continuous-assessment', 130),
    (v_product_id, 'centralized_results', 'university_admin', 'Learner Records', 'Centralized Results', '/university-admin/learners/results', 140),
    (v_product_id, 'certificate_generation', 'university_admin', 'Learner Records', 'Certificate Generation', '/university-admin/learners/certificates', 150),
    -- ── university_admin — Examination Management ──────────────────────
    (v_product_id, 'examination_scheduling', 'university_admin', 'Examination Management', 'Examination Scheduling', '/university-admin/examinations', 160),
    (v_product_id, 'grade_calculation', 'university_admin', 'Examination Management', 'Grade Calculation', '/university-admin/examinations/grades', 170),
    (v_product_id, 'results_publishing', 'university_admin', 'Examination Management', 'Results Publishing', '/university-admin/examinations/results', 180),
    -- ── university_admin — Placement & Industry Linkages ───────────────
    (v_product_id, 'placement_readiness', 'university_admin', 'Placement & Industry Linkages', 'Placement Readiness', '/university-admin/placements/readiness', 190),
    (v_product_id, 'company_database', 'university_admin', 'Placement & Industry Linkages', 'Company Database', '/university-admin/placements/companies', 200),
    (v_product_id, 'internship_reports', 'university_admin', 'Placement & Industry Linkages', 'Internship Reports', '/university-admin/placements/internships', 210),
    (v_product_id, 'mous_partnerships', 'university_admin', 'Placement & Industry Linkages', 'MoUs & Partnerships', '/university-admin/placements/mous', 220),
    -- ── university_admin — Finance & Fees ───────────────────────────────
    (v_product_id, 'fee_structures', 'university_admin', 'Finance & Fees', 'Fee Structures', '/university-admin/finance', 230),
    (v_product_id, 'payment_tracking', 'university_admin', 'Finance & Fees', 'Payment Tracking', '/university-admin/finance/payments', 240),
    (v_product_id, 'financial_reports', 'university_admin', 'Finance & Fees', 'Financial Reports', '/university-admin/finance/reports', 250),
    -- ── university_admin — Analytics & Compliance ───────────────────────
    (v_product_id, 'district_college_reports', 'university_admin', 'Analytics & Compliance', 'District & College Reports', '/university-admin/analytics/reports', 260),
    (v_product_id, 'basic_analytics', 'university_admin', 'Analytics & Compliance', 'Course Analytics', '/university-admin/analytics/course-analytics', 270),
    (v_product_id, 'scheme_compliance', 'university_admin', 'Analytics & Compliance', 'Scheme Compliance (TNSDC)', '/university-admin/analytics/compliance', 280),
    (v_product_id, 'obe_tracking', 'university_admin', 'Analytics & Compliance', 'OBE Tracking', '/university-admin/analytics/obe-tracking', 290),
    -- ── university_admin — Library & Learner Services ──────────────────
    (v_product_id, 'library_management', 'university_admin', 'Library & Learner Services', 'Library Management', '/university-admin/library/management', 300),
    (v_product_id, 'library_clearance', 'university_admin', 'Library & Learner Services', 'Library Clearance', '/university-admin/library/clearance', 310),
    (v_product_id, 'learner_service_requests', 'university_admin', 'Library & Learner Services', 'Learner Service Requests', '/university-admin/library/service-requests', 320),
    (v_product_id, 'graduation_integration', 'university_admin', 'Library & Learner Services', 'Graduation Integration', '/university-admin/library/graduation-integration', 330),
    -- ── university_admin — HR & Payroll ─────────────────────────────────
    (v_product_id, 'faculty_lifecycle', 'university_admin', 'HR & Payroll', 'Faculty Lifecycle', '/university-admin/hr/faculty-lifecycle', 340),
    (v_product_id, 'staff_management', 'university_admin', 'HR & Payroll', 'Staff Management', '/university-admin/hr/staff-management', 350),
    (v_product_id, 'payroll_processing', 'university_admin', 'HR & Payroll', 'Payroll Processing', '/university-admin/hr/payroll', 360),
    (v_product_id, 'statutory_deductions', 'university_admin', 'HR & Payroll', 'Statutory Deductions', '/university-admin/hr/statutory-deductions', 370),
    (v_product_id, 'employee_records', 'university_admin', 'HR & Payroll', 'Employee Records', '/university-admin/hr/employee-records', 380),
    (v_product_id, 'leave_management', 'university_admin', 'HR & Payroll', 'Leave Management', '/university-admin/hr/leave-management', 390),
    -- ── university_admin — Communication & Announcements ────────────────
    (v_product_id, 'circulars_notices', 'university_admin', 'Communication & Announcements', 'Circulars & Notices', '/university-admin/communication/circulars', 400),
    (v_product_id, 'training_updates', 'university_admin', 'Communication & Announcements', 'Training Updates', '/university-admin/communication/training', 410)

  ON CONFLICT (product_id, role, key) DO UPDATE SET
    nav_group = EXCLUDED.nav_group,
    nav_label = EXCLUDED.nav_label,
    nav_path = EXCLUDED.nav_path,
    display_order = EXCLUDED.display_order,
    is_active = true,
    updated_at = now();
END $$;
