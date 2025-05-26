import type { NextApiRequest, NextApiResponse } from 'next';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY! // MUST be service role key
);

const allowedOrigins = [
  'https://trackship-flow-central.vercel.app',
  'http://localhost:8080'
];,.

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const origin = req.headers.origin;
if (typeof origin === 'string' && allowedOrigins.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

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
    const { data: existingUsers, error: fetchError } = await supabase.auth.admin.listUsers({ page: 1, perPage: 100 });
    const alreadyExists = existingUsers?.users.find(user => user.email === email);
    if (alreadyExists) {
      return res.status(409).json({ error: 'A user with this email already exists' });
    }

    const { data: authUser, error: authError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });

    if (authError || !authUser?.user?.id) {
      return res.status(400).json({ error: authError?.message || 'Failed to create auth user' });
    }

    const userId = authUser.user.id;
    const { error: userInsertError } = await supabase.from('users').insert([{
      id: userId,
      name,
      username: email,
      is_admin: permissions.includes('admin')
    }]);

    if (userInsertError) {
      return res.status(500).json({ error: userInsertError.message });
    }

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
