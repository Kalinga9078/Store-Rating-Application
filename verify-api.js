const assert = require('assert');

const BASE_URL = 'http://localhost:3000';

// Colors for console logs
const green = '\x1b[32m';
const red = '\x1b[31m';
const reset = '\x1b[0m';

async function testSuite() {
  console.log('--- Starting Store Ratings API Verification ---');
  
  // Helpers
  async function api(path, method = 'GET', body = null, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    
    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);
    
    const res = await fetch(`${BASE_URL}${path}`, options);
    let data = {};
    try {
      data = await res.json();
    } catch (e) {}
    
    return { status: res.status, data };
  }

  let adminToken = null;
  let userToken = null;
  let ownerToken = null;
  
  // Test names
  const testNormalUserEmail = `user.${Date.now()}@test.com`;
  const testStoreEmail = `store.${Date.now()}@test.com`;
  
  // 1. Admin Login
  console.log('\n[1] Testing Administrator Login...');
  const adminLogin = await api('/api/auth/login', 'POST', {
    email: 'admin@starrater.com',
    password: 'Admin123!'
  });
  
  assert.strictEqual(adminLogin.status, 200, 'Admin login failed');
  assert.ok(adminLogin.data.token, 'Token not returned');
  adminToken = adminLogin.data.token;
  console.log(`${green}✔ Admin logged in successfully!${reset}`);

  // 2. Validate Constraints
  console.log('\n[2] Testing Form Validation Constraints...');
  
  // Name too short (under 20 chars)
  const shortNameRes = await api('/api/auth/register', 'POST', {
    name: 'Short User',
    email: 'invalid.user@test.com',
    address: '123 Test Lane',
    password: 'Password123!'
  });
  assert.strictEqual(shortNameRes.status, 400);
  assert.ok(shortNameRes.data.error.includes('Name'), 'Short name check failed');
  console.log(`${green}✔ Validated: Name minimum length (under 20 chars rejected)${reset}`);

  // Invalid email
  const badEmailRes = await api('/api/auth/register', 'POST', {
    name: 'Regular Normal Test User Long Name',
    email: 'bademail',
    address: '123 Test Lane',
    password: 'Password123!'
  });
  assert.strictEqual(badEmailRes.status, 400);
  console.log(`${green}✔ Validated: Invalid email format rejected${reset}`);

  // Invalid password (no special char)
  const badPassRes = await api('/api/auth/register', 'POST', {
    name: 'Regular Normal Test User Long Name',
    email: 'good.email@test.com',
    address: '123 Test Lane',
    password: 'PasswordNoSpecial'
  });
  assert.strictEqual(badPassRes.status, 400);
  console.log(`${green}✔ Validated: Password complexity (no special character rejected)${reset}`);

  // 3. User Registration (Valid)
  console.log('\n[3] Testing User Registration...');
  const regRes = await api('/api/auth/register', 'POST', {
    name: 'Regular Normal Test User Long Name',
    email: testNormalUserEmail,
    address: '456 User Residential Area Road, Apt 2B',
    password: 'UserPass123!'
  });
  assert.strictEqual(regRes.status, 201, 'User registration failed');
  console.log(`${green}✔ Registered a normal user successfully!${reset}`);

  // 4. Normal User Login
  console.log('\n[4] Testing Normal User Login...');
  const userLogin = await api('/api/auth/login', 'POST', {
    email: testNormalUserEmail,
    password: 'UserPass123!'
  });
  assert.strictEqual(userLogin.status, 200, 'User login failed');
  userToken = userLogin.data.token;
  console.log(`${green}✔ Normal user logged in!${reset}`);

  // 5. Admin Add Store
  console.log('\n[5] Testing Admin Add Store (Creates Store + Owner User)...');
  const storeRes = await api('/api/admin/stores', 'POST', {
    name: 'Gourmet Delicacies Super Store',
    email: testStoreEmail,
    address: '789 Business Ave, Tech Park Plaza',
    password: 'OwnerPass123!'
  }, adminToken);
  assert.strictEqual(storeRes.status, 201, 'Store creation failed');
  console.log(`${green}✔ Added new store & owner account successfully!${reset}`);

  // 6. Store Owner Login
  console.log('\n[6] Testing Store Owner Login...');
  const ownerLogin = await api('/api/auth/login', 'POST', {
    email: testStoreEmail,
    password: 'OwnerPass123!'
  });
  assert.strictEqual(ownerLogin.status, 200, 'Owner login failed');
  ownerToken = ownerLogin.data.token;
  console.log(`${green}✔ Store Owner logged in successfully!${reset}`);

  // 7. Normal User Rating Flow
  console.log('\n[7] Testing Store Ratings...');
  
  // Get stores list
  const storesList1 = await api('/api/stores', 'GET', null, userToken);
  assert.strictEqual(storesList1.status, 200);
  const targetStore = storesList1.data.find(s => s.email === testStoreEmail);
  assert.ok(targetStore, 'Created store not found in user listings');
  assert.strictEqual(targetStore.user_rating, null, 'User rating should initially be null');
  
  // Submit rating (4 stars)
  const submitRatingRes = await api('/api/ratings', 'POST', {
    store_id: targetStore.id,
    rating: 4
  }, userToken);
  assert.strictEqual(submitRatingRes.status, 201, 'Rating submission failed');
  console.log(`${green}✔ Submitted 4-star rating successfully!${reset}`);

  // Verify average rating update
  const storesList2 = await api('/api/stores', 'GET', null, userToken);
  const updatedStore = storesList2.data.find(s => s.email === testStoreEmail);
  assert.strictEqual(updatedStore.average_rating, 4, 'Average rating did not update to 4');
  assert.strictEqual(updatedStore.user_rating, 4, 'User rating did not record as 4');
  console.log(`${green}✔ Verified: Average rating is updated to 4.0${reset}`);

  // Modify rating to 5 stars
  const modifyRatingRes = await api(`/api/ratings/${targetStore.id}`, 'PUT', {
    rating: 5
  }, userToken);
  assert.strictEqual(modifyRatingRes.status, 200, 'Rating modification failed');
  console.log(`${green}✔ Modified rating to 5 stars successfully!${reset}`);

  // Verify updated average rating
  const storesList3 = await api('/api/stores', 'GET', null, userToken);
  const finalStore = storesList3.data.find(s => s.email === testStoreEmail);
  assert.strictEqual(finalStore.average_rating, 5, 'Average rating did not update to 5');
  assert.strictEqual(finalStore.user_rating, 5, 'User rating did not record as 5');
  console.log(`${green}✔ Verified: Average rating is updated to 5.0${reset}`);

  // 8. Store Owner Dashboard Reviewers
  console.log('\n[8] Testing Store Owner Dashboard API...');
  const ownerDash = await api('/api/owner/dashboard', 'GET', null, ownerToken);
  assert.strictEqual(ownerDash.status, 200);
  assert.strictEqual(ownerDash.data.averageRating, 5);
  assert.strictEqual(ownerDash.data.reviewers.length, 1, 'Reviewers list count should be 1');
  assert.strictEqual(ownerDash.data.reviewers[0].rating, 5);
  assert.strictEqual(ownerDash.data.reviewers[0].email, testNormalUserEmail);
  console.log(`${green}✔ Store Owner dashboard correctly displays average rating and reviewer info!${reset}`);

  // 9. Admin view owner details (with rating)
  console.log('\n[9] Testing Admin View User Details (including Store Owner Rating)...');
  // First, find the owner user ID from admin users list or we can get it from admin stores list
  const adminStoresList = await api('/api/admin/stores', 'GET', null, adminToken);
  const adminTargetStore = adminStoresList.data.find(s => s.email === testStoreEmail);
  assert.ok(adminTargetStore.owner_id, 'owner_id missing in store object');
  
  const ownerDetails = await api(`/api/admin/users/${adminTargetStore.owner_id}`, 'GET', null, adminToken);
  assert.strictEqual(ownerDetails.status, 200);
  assert.strictEqual(ownerDetails.data.role, 'owner');
  assert.strictEqual(ownerDetails.data.average_rating, 5, 'Admin details for store owner missing rating info');
  console.log(`${green}✔ Store Owner average rating (5.0) correctly displays in Administrator User Details!${reset}`);

  // 10. Update Password Flow
  console.log('\n[10] Testing Update Password Flow...');
  const changePassRes = await api('/api/auth/change-password', 'POST', {
    currentPassword: 'UserPass123!',
    newPassword: 'NewUserPass99!'
  }, userToken);
  assert.strictEqual(changePassRes.status, 200, 'Change password failed');
  
  // Verify user cannot login with old password anymore
  const oldLoginRes = await api('/api/auth/login', 'POST', {
    email: testNormalUserEmail,
    password: 'UserPass123!'
  });
  assert.strictEqual(oldLoginRes.status, 400, 'Login with old password should fail');
  
  // Verify user can login with new password
  const newLoginRes = await api('/api/auth/login', 'POST', {
    email: testNormalUserEmail,
    password: 'NewUserPass99!'
  });
  assert.strictEqual(newLoginRes.status, 200, 'Login with new password failed');
  console.log(`${green}✔ Password updated successfully and verified via login!${reset}`);

  console.log(`\n${green}========================================`);
  console.log(`🎉 ALL API ENDPOINT TESTS PASSED SUCCESSFULLY!`);
  console.log(`========================================${reset}`);
}

testSuite().catch(err => {
  console.error(`\n${red}❌ Test suite failed with error:${reset}`, err);
  process.exit(1);
});
