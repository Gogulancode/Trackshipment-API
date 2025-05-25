// /pages/api/create-user.ts (Next.js API route or any backend handler)
import { NextApiRequest, NextApiResponse } from 'next';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY! // MUST be service role key
);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const apiKey = req.headers.authorization || req.headers['x-api-key'];
  if (apiKey !== process.env.ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { name, email, password, permissions = [] } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  try {
    // Check if user already exists
    const { data: existingUsers, error: fetchError } = await supabase.auth.admin.listUsers({
      page: 1,
      perPage: 100
    });

    const alreadyExists = existingUsers?.users.find(user => user.email === email);
    if (alreadyExists) {
      return res.status(409).json({ error: 'A user with this email already exists' });
    }

    // 1. Create user in Supabase Auth
    const { data: authUser, error: authError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });

    if (authError || !authUser?.user?.id) {
      return res.status(400).json({ error: authError?.message || 'Failed to create auth user' });
    }

    const userId = authUser.user.id;

    // 2. Insert into custom users table
    const { error: userInsertError } = await supabase.from('users').insert([{
      id: userId,
      name,
      username: email,
      is_admin: permissions.includes('admin')
    }]);

    if (userInsertError) {
      return res.status(500).json({ error: userInsertError.message });
    }

    // 3. Insert permissions
    let allPermissions = [...permissions];

    if (permissions.includes('admin')) {
      allPermissions = [
        'can_create_product', 'can_edit_product', 'can_delete_product',
        'can_create_vendor', 'can_edit_vendor', 'can_delete_vendor',
        'can_create_transporter', 'can_edit_transporter', 'can_delete_transporter',
        'can_create_po', 'can_edit_po', 'can_delete_po',
        'can_create_shipment', 'can_edit_shipment', 'can_delete_shipment',
        'can_create_appointment', 'can_edit_appointment', 'can_delete_appointment',
        'can_view_reports', 'can_download_reports', 'can_manage_users'
      ];
    }

    const uniquePerms = Array.from(new Set(allPermissions.filter(p => p !== 'admin')));

    if (uniquePerms.length > 0) {
      const perms = uniquePerms.map((p: string) => ({ user_id: userId, permission: p }));
      await supabase.from('permissions').insert(perms);
    }

    return res.status(200).json({ message: 'User created successfully' });
  } catch (err) {
    console.error('Unexpected error:', err);
    return res.status(500).json({ error: 'Unexpected error', details: err });
  }
}

