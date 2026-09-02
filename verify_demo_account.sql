-- Verify Demo College Admin Account
SELECT 
    u.id as user_id,
    u.email,
    u.is_email_verified,
    u.is_blocked,
    o.name as organization,
    o.slug as org_slug,
    r.name as role,
    s.plan_code,
    s.status as subscription_status,
    s.subscription_end_date
FROM public.users u
LEFT JOIN public.memberships m ON u.id = m.user_id
LEFT JOIN public.organizations o ON m.org_id = o.id
LEFT JOIN public.membership_roles mr ON m.id = mr.membership_id
LEFT JOIN public.roles r ON mr.role_id = r.id
LEFT JOIN public.subscriptions s ON u.id = s.user_id
WHERE u.email = 'demo.college@skillpassport.com';
