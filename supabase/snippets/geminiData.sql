DO $$
DECLARE
  v_user_id     uuid := '59dc759d-45ff-4d14-b7f3-34c435cbf4ae';
  v_product_id  uuid := '7352d0f4-88a6-4e14-9421-6c5706791973'; -- lte
  v_org_id      uuid;
  v_membership_id uuid;
BEGIN
  -- 1. Find the user's membership and org
  SELECT m.id, m.org_id
    INTO v_membership_id, v_org_id
    FROM memberships m
   WHERE m.user_id = v_user_id
   LIMIT 1;

  IF v_membership_id IS NULL THEN
    RAISE EXCEPTION 'No membership found for user %', v_user_id;
  END IF;

  RAISE NOTICE 'Found membership_id=%, org_id=%', v_membership_id, v_org_id;

  -- 2. Activate lte for the org
  INSERT INTO organization_products (org_id, product_id, active)
  VALUES (v_org_id, v_product_id, true)
  ON CONFLICT (org_id, product_id) DO UPDATE SET active = true;

  -- 3. Link the membership to lte
  INSERT INTO membership_products (membership_id, product_id)
  VALUES (v_membership_id, v_product_id)
  ON CONFLICT (membership_id, product_id) DO NOTHING;

  RAISE NOTICE 'Done. lte product activated for org=% and linked to membership=%', v_org_id, v_membership_id;
END;
$$;
