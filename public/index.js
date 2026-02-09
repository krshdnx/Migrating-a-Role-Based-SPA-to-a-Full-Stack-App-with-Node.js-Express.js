async function loginUser(username, password) {
    try {
        const response = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });     
            
        const data = await response.json();

        if (response.ok) {
            // Save token in memory (or sessionStorage for page refresh)
             sessionStorage.setItem('auth_token', data.token);
             showDashboard(data.user);
        } else {
            alert ('Login failed: ' + data.error);
        }
        } catch (error) {
            alert('Network error');
        }
    }

    function getAuthHeader() {
        const token = sessionStorage.getItem('auth_token');
        return token ? { Authorization: 'Bearer $token'  } : {};
    }

    // Example: Fetch admin data
    async function loadAdminDashboard() {
        const res = await fetch('http://localhost:3000/api/admin/dashboard', {
            headers: getAuthHeader()
        });
        if (res.ok) {
            const data = await res.json();
            document.getElementById('content').innerText = data.message;
        } else {
            document.getElementById('content').innerText = 'Access denied';
        }
    }


        

// ============================================
// GLOBAL VARIABLES & CONSTANTS
// ============================================

const STORAGE_KEY = 'ipt_demo_v1';
let currentUser = null;

// Initialize database structure
window.db = {
  accounts: [],
  departments: [],
  employees: [],
  requests: []
};

// ============================================
// DATA PERSISTENCE
// ============================================

function loadFromStorage() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      window.db = JSON.parse(stored);
    } else {
      // Seed initial data
      seedInitialData();
      saveToStorage();
    }
  } catch (error) {
    console.error('Error loading from storage:', error);
    seedInitialData();
    saveToStorage();
  }
}



function seedInitialData() {
  window.db = {
    accounts: [
      {
        email: 'admin@example.com',
        password: 'Password123!',
        firstName: 'Admin',
        lastName: 'User',
        role: 'admin',
        verified: true
      }
    ],
    departments: [
      { id: 1, name: 'Engineering', description: 'Software development team' },
      { id: 2, name: 'HR', description: 'Human Resources department' }
    ],
    employees: [],
    requests: []
  };
  
  // Generate unique IDs for departments
  let deptIdCounter = 3;
  window.db.departments.forEach((dept, index) => {
    if (!dept.id) dept.id = index + 1;
    if (deptIdCounter <= dept.id) deptIdCounter = dept.id + 1;
  });
  
  // Store counter for future IDs
  window.db._counters = { departmentId: deptIdCounter, employeeId: 1, requestId: 1 };
}

// ============================================
// ROUTING SYSTEM
// ============================================

function navigateTo(hash) {
  window.location.hash = hash;
}

function handleRouting() {
  const hash = window.location.hash.slice(1) || '/';
  const route = hash.split('?')[0];
  
  // Hide all pages
  document.querySelectorAll('.page').forEach(page => {
    page.classList.remove('active');
  });
  
  // Protected routes (require authentication)
  const protectedRoutes = ['/profile', '/requests', '/employees', '/departments', '/accounts'];
  const adminRoutes = ['/employees', '/departments', '/accounts'];
  
  if (protectedRoutes.includes(route) && !currentUser) {
    showToast('Please login to access this page', 'warning');
    navigateTo('/login');
    return;
  }
  
  if (adminRoutes.includes(route) && (!currentUser || currentUser.role !== 'admin')) {
    showToast('Admin access required', 'danger');
    navigateTo('/');
    return;
  }
  
  // Show appropriate page
  const pageMap = {
    '/': 'home-page',
    '/register': 'register-page',
    '/verify-email': 'verify-email-page',
    '/login': 'login-page',
    '/profile': 'profile-page',
    '/employees': 'employees-page',
    '/departments': 'departments-page',
    '/accounts': 'accounts-page',
    '/requests': 'requests-page'
  };
  
  const pageId = pageMap[route];
  if (pageId) {
    const page = document.getElementById(pageId);
    if (page) {
      page.classList.add('active');
      
      // Call render functions for specific pages
      if (route === '/profile') {
        renderProfile();
      } else if (route === '/employees') {
        renderEmployeesTable();
      } else if (route === '/departments') {
        renderDepartmentsTable();
      } else if (route === '/accounts') {
        renderAccountsTable();
      } else if (route === '/requests') {
        renderRequestsTable();
      }
    }
  } else {
    // Default to home
    document.getElementById('home-page').classList.add('active');
  }
}

// ============================================
// AUTHENTICATION
// ============================================

function setAuthState(isAuth, user = null) {
  currentUser = user;
  const body = document.body;
  
  if (isAuth && user) {
    body.classList.remove('not-authenticated');
    body.classList.add('authenticated');
    
    if (user.role === 'admin') {
      body.classList.add('is-admin');
    } else {
      body.classList.remove('is-admin');
    }
    
    // Update navbar username
    const usernameEl = document.getElementById('navbar-username');
    if (usernameEl) {
      usernameEl.textContent = `${user.firstName} ${user.lastName}`;
    }
  } else {
    body.classList.remove('authenticated', 'is-admin');
    body.classList.add('not-authenticated');
    currentUser = null;
  }
}

function checkAuthOnLoad() {
  const authToken = localStorage.getItem('auth_token');
  if (authToken) {
    const account = window.db.accounts.find(acc => acc.email === authToken && acc.verified);
    if (account) {
      setAuthState(true, account);
    } else {
      localStorage.removeItem('auth_token');
    }
  }
}

function logout() {
  localStorage.removeItem('auth_token');
  setAuthState(false);
  navigateTo('/');
  showToast('Logged out successfully', 'success');
}

// ============================================
// REGISTRATION
// ============================================

function handleRegister(e) {
  e.preventDefault();
  
  const firstName = document.getElementById('reg-firstname').value.trim();
  const lastName = document.getElementById('reg-lastname').value.trim();
  const email = document.getElementById('reg-email').value.trim().toLowerCase();
  const password = document.getElementById('reg-password').value;
  
  const errorEl = document.getElementById('register-error');
  
  // Check if email already exists
  const existingAccount = window.db.accounts.find(acc => acc.email === email);
  if (existingAccount) {
    errorEl.textContent = 'Email already registered';
    errorEl.style.display = 'block';
    return;
  }
  
  // Validate password length
  if (password.length < 6) {
    errorEl.textContent = 'Password must be at least 6 characters';
    errorEl.style.display = 'block';
    return;
  }
  
  // Create new account
  const newAccount = {
    email,
    password,
    firstName,
    lastName,
    role: 'user',
    verified: false
  };
  
  window.db.accounts.push(newAccount);
  saveToStorage();
  
  // Store unverified email
  localStorage.setItem('unverified_email', email);
  
  // Clear form
  document.getElementById('register-form').reset();
  errorEl.style.display = 'none';
  
  // Navigate to verify email page
  navigateTo('/verify-email');
}

// ============================================
// EMAIL VERIFICATION
// ============================================

function renderVerifyEmailPage() {
  const email = localStorage.getItem('unverified_email');
  const emailDisplay = document.getElementById('verify-email-display');
  if (emailDisplay && email) {
    emailDisplay.textContent = email;
  }
}

function simulateEmailVerification() {
  const email = localStorage.getItem('unverified_email');
  if (!email) {
    showToast('No email to verify', 'warning');
    return;
  }
  
  const account = window.db.accounts.find(acc => acc.email === email);
  if (account) {
    account.verified = true;
    saveToStorage();
    localStorage.removeItem('unverified_email');
    showToast('Email verified successfully!', 'success');
    navigateTo('/login');
  } else {
    showToast('Account not found', 'danger');
  }
}

// ============================================
// LOGIN
// ============================================

function handleLogin(e) {
  e.preventDefault();
  
  const email = document.getElementById('login-email').value.trim().toLowerCase();
  const password = document.getElementById('login-password').value;
  
  const errorEl = document.getElementById('login-error');
  
  const account = window.db.accounts.find(
    acc => acc.email === email && acc.password === password && acc.verified === true
  );
  
  if (account) {
    // Save auth token
    localStorage.setItem('auth_token', email);
    setAuthState(true, account);
    
    // Clear form
    document.getElementById('login-form').reset();
    errorEl.style.display = 'none';
    
    showToast('Login successful!', 'success');
    navigateTo('/profile');
  } else {
    errorEl.textContent = 'Invalid email, password, or account not verified';
    errorEl.style.display = 'block';
  }
}

// ============================================
// PROFILE PAGE
// ============================================

let isEditingProfile = false;

function renderProfile() {
  if (!currentUser) {
    isEditingProfile = false;
    return;
  }
  
  const content = document.getElementById('profile-content');
  
  if (isEditingProfile) {
    // Show edit form
    content.innerHTML = `
      <div class="row">
        <div class="col-md-6">
          <h5>Edit Profile</h5>
          <form id="edit-profile-form">
            <div class="mb-3">
              <label for="edit-firstname" class="form-label">First Name</label>
              <input type="text" class="form-control" id="edit-firstname" value="${currentUser.firstName}" required minlength="2">
              <div class="invalid-feedback">First name must be at least 2 characters</div>
            </div>
            <div class="mb-3">
              <label for="edit-lastname" class="form-label">Last Name</label>
              <input type="text" class="form-control" id="edit-lastname" value="${currentUser.lastName}" required minlength="2">
              <div class="invalid-feedback">Last name must be at least 2 characters</div>
            </div>
            <div class="mb-3">
              <label for="edit-email" class="form-label">Email</label>
              <input type="email" class="form-control" id="edit-email" value="${currentUser.email}" disabled>
              <small class="form-text text-muted">Email cannot be changed</small>
            </div>
            <div class="mb-3">
              <label for="edit-role" class="form-label">Role</label>
              <input type="text" class="form-control" id="edit-role" value="${currentUser.role}" disabled>
              <small class="form-text text-muted">Role cannot be changed</small>
            </div>
            <div class="mb-3">
              <label for="edit-password" class="form-label">New Password</label>
              <input type="password" class="form-control" id="edit-password" placeholder="Leave blank to keep current password" minlength="6">
              <div class="invalid-feedback">Password must be at least 6 characters if provided</div>
              <small class="form-text text-muted">Leave blank to keep your current password</small>
            </div>
            <div id="edit-profile-error" class="alert alert-danger" style="display: none;"></div>
            <div class="d-flex gap-2">
              <button type="submit" class="btn btn-primary">Save Changes</button>
              <button type="button" class="btn btn-secondary" onclick="cancelEditProfile()">Cancel</button>
            </div>
          </form>
        </div>
      </div>
    `;
    
    // Attach form submit handler
    document.getElementById('edit-profile-form').addEventListener('submit', handleEditProfile);
  } else {
    // Show profile view
    content.innerHTML = `
      <div class="row">
        <div class="col-md-6">
          <h5>Personal Information</h5>
          <table class="table">
            <tr>
              <th>Name:</th>
              <td>${currentUser.firstName} ${currentUser.lastName}</td>
            </tr>
            <tr>
              <th>Email:</th>
              <td>${currentUser.email}</td>
            </tr>
            <tr>
              <th>Role:</th>
              <td><span class="badge bg-${currentUser.role === 'admin' ? 'danger' : 'primary'}">${currentUser.role}</span></td>
            </tr>
          </table>
          <button class="btn btn-primary" onclick="showEditProfileForm()">
            Edit Profile
          </button>
        </div>
      </div>
    `;
  }
}

function showEditProfileForm() {
  isEditingProfile = true;
  renderProfile();
}

function cancelEditProfile() {
  isEditingProfile = false;
  renderProfile();
}

function handleEditProfile(e) {
  e.preventDefault();
  
  const firstName = document.getElementById('edit-firstname').value.trim();
  const lastName = document.getElementById('edit-lastname').value.trim();
  const password = document.getElementById('edit-password').value;
  const errorEl = document.getElementById('edit-profile-error');
  const form = document.getElementById('edit-profile-form');
  
  // Clear previous errors
  errorEl.style.display = 'none';
  errorEl.textContent = '';
  
  // Validate first name
  if (firstName.length < 2) {
    errorEl.textContent = 'First name must be at least 2 characters';
    errorEl.style.display = 'block';
    document.getElementById('edit-firstname').classList.add('is-invalid');
    return;
  } else {
    document.getElementById('edit-firstname').classList.remove('is-invalid');
  }
  
  // Validate last name
  if (lastName.length < 2) {
    errorEl.textContent = 'Last name must be at least 2 characters';
    errorEl.style.display = 'block';
    document.getElementById('edit-lastname').classList.add('is-invalid');
    return;
  } else {
    document.getElementById('edit-lastname').classList.remove('is-invalid');
  }
  
  // Validate password if provided
  if (password && password.length < 6) {
    errorEl.textContent = 'Password must be at least 6 characters if provided';
    errorEl.style.display = 'block';
    document.getElementById('edit-password').classList.add('is-invalid');
    return;
  } else {
    document.getElementById('edit-password').classList.remove('is-invalid');
  }
  
  // Find and update the user account
  const account = window.db.accounts.find(acc => acc.email === currentUser.email);
  if (account) {
    account.firstName = firstName;
    account.lastName = lastName;
    
    // Only update password if provided
    if (password) {
      account.password = password;
    }
    
    // Update currentUser object
    currentUser.firstName = firstName;
    currentUser.lastName = lastName;
    if (password) {
      currentUser.password = password;
    }
    
    // Save to storage
    saveToStorage();
    
    // Update navbar username
    const usernameEl = document.getElementById('navbar-username');
    if (usernameEl) {
      usernameEl.textContent = `${firstName} ${lastName}`;
    }
    
    // Hide form and show profile
    isEditingProfile = false;
    renderProfile();
    
    // Show success toast
    showToast('Profile updated successfully!', 'success');
  } else {
    errorEl.textContent = 'Account not found';
    errorEl.style.display = 'block';
  }
}

// ============================================
// ACCOUNTS MANAGEMENT (Admin)
// ============================================

function renderAccountsTable() {
  const container = document.getElementById('accounts-table-container');
  if (!container) return;
  
  const accounts = window.db.accounts;
  
  if (accounts.length === 0) {
    container.innerHTML = '<p class="text-muted">No accounts found</p>';
    return;
  }
  
  let html = `
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Role</th>
            <th>Verified</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  accounts.forEach(account => {
    html += `
      <tr>
        <td>${account.firstName} ${account.lastName}</td>
        <td>${account.email}</td>
        <td><span class="badge bg-${account.role === 'admin' ? 'danger' : 'primary'}">${account.role}</span></td>
        <td>${account.verified ? '<span class="badge bg-success">✓</span>' : '<span class="badge bg-secondary">—</span>'}</td>
        <td>
          <button class="btn btn-sm btn-primary" onclick="editAccount('${account.email}')">Edit</button>
          <button class="btn btn-sm btn-warning" onclick="resetPassword('${account.email}')">Reset PW</button>
          <button class="btn btn-sm btn-danger" onclick="deleteAccount('${account.email}')">Delete</button>
        </td>
      </tr>
    `;
  });
  
  html += `
        </tbody>
      </table>
    </div>
  `;
  
  container.innerHTML = html;
}

function openAccountForm(email = null) {
  const form = document.getElementById('account-form');
  const modalTitle = document.getElementById('accountModalTitle');
  const editEmailInput = document.getElementById('account-edit-email');
  
  form.reset();
  
  if (email) {
    // Edit mode
    const account = window.db.accounts.find(acc => acc.email === email);
    if (account) {
      modalTitle.textContent = 'Edit Account';
      editEmailInput.value = email;
      document.getElementById('account-firstname').value = account.firstName;
      document.getElementById('account-lastname').value = account.lastName;
      document.getElementById('account-email').value = account.email;
      document.getElementById('account-email').disabled = true; // Don't allow email change
      document.getElementById('account-password').required = false;
      document.getElementById('account-role').value = account.role;
      document.getElementById('account-verified').checked = account.verified;
    }
  } else {
    // Add mode
    modalTitle.textContent = 'Add Account';
    editEmailInput.value = '';
    document.getElementById('account-email').disabled = false;
    document.getElementById('account-password').required = true;
  }
}

function saveAccount() {
  const form = document.getElementById('account-form');
  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return;
  }
  
  const editEmail = document.getElementById('account-edit-email').value;
  const firstName = document.getElementById('account-firstname').value.trim();
  const lastName = document.getElementById('account-lastname').value.trim();
  const email = document.getElementById('account-email').value.trim().toLowerCase();
  const password = document.getElementById('account-password').value;
  const role = document.getElementById('account-role').value;
  const verified = document.getElementById('account-verified').checked;
  
  if (editEmail) {
    // Edit existing
    const account = window.db.accounts.find(acc => acc.email === editEmail);
    if (account) {
      account.firstName = firstName;
      account.lastName = lastName;
      account.role = role;
      account.verified = verified;
      if (password) {
        if (password.length < 6) {
          showToast('Password must be at least 6 characters', 'warning');
          return;
        }
        account.password = password;
      }
      saveToStorage();
      renderAccountsTable();
      bootstrap.Modal.getInstance(document.getElementById('accountModal')).hide();
      showToast('Account updated successfully', 'success');
    }
  } else {
    // Add new
    if (window.db.accounts.find(acc => acc.email === email)) {
      showToast('Email already exists', 'danger');
      return;
    }
    
    if (!password || password.length < 6) {
      showToast('Password must be at least 6 characters', 'warning');
      return;
    }
    
    window.db.accounts.push({
      email,
      password,
      firstName,
      lastName,
      role,
      verified
    });
    saveToStorage();
    renderAccountsTable();
    bootstrap.Modal.getInstance(document.getElementById('accountModal')).hide();
    showToast('Account created successfully', 'success');
  }
}

function editAccount(email) {
  openAccountForm(email);
  const modal = new bootstrap.Modal(document.getElementById('accountModal'));
  modal.show();
}

function resetPassword(email) {
  const newPassword = prompt('Enter new password (min 6 characters):');
  if (!newPassword) return;
  
  if (newPassword.length < 6) {
    showToast('Password must be at least 6 characters', 'warning');
    return;
  }
  
  const account = window.db.accounts.find(acc => acc.email === email);
  if (account) {
    account.password = newPassword;
    saveToStorage();
    showToast('Password reset successfully', 'success');
  }
}

function deleteAccount(email) {
  if (currentUser && currentUser.email === email) {
    showToast('Cannot delete your own account', 'danger');
    return;
  }
  
  if (confirm(`Are you sure you want to delete account ${email}?`)) {
    window.db.accounts = window.db.accounts.filter(acc => acc.email !== email);
    // Also remove associated employee
    window.db.employees = window.db.employees.filter(emp => emp.userEmail !== email);
    saveToStorage();
    renderAccountsTable();
    showToast('Account deleted successfully', 'success');
  }
}

// ============================================
// DEPARTMENTS MANAGEMENT (Admin)
// ============================================

function renderDepartmentsTable() {
  const container = document.getElementById('departments-table-container');
  if (!container) return;
  
  const departments = window.db.departments;
  
  if (departments.length === 0) {
    container.innerHTML = '<p class="text-muted">No departments found</p>';
    return;
  }
  
  let html = `
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
          <tr>
            <th>Name</th>
            <th>Description</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  departments.forEach((dept, index) => {
    html += `
      <tr>
        <td>${dept.name}</td>
        <td>${dept.description || '—'}</td>
        <td>
          <button class="btn btn-sm btn-primary" onclick="editDepartment(${index})">Edit</button>
          <button class="btn btn-sm btn-danger" onclick="deleteDepartment(${index})">Delete</button>
        </td>
      </tr>
    `;
  });
  
  html += `
        </tbody>
      </table>
    </div>
  `;
  
  container.innerHTML = html;
}

function openDepartmentForm(index = null) {
  const form = document.getElementById('department-form');
  const editIdInput = document.getElementById('department-edit-id');
  
  form.reset();
  
  if (index !== null) {
    const dept = window.db.departments[index];
    if (dept) {
      editIdInput.value = index;
      document.getElementById('department-name').value = dept.name;
      document.getElementById('department-description').value = dept.description || '';
    }
  } else {
    editIdInput.value = '';
  }
}

function saveDepartment() {
  const form = document.getElementById('department-form');
  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return;
  }
  
  const editIndex = document.getElementById('department-edit-id').value;
  const name = document.getElementById('department-name').value.trim();
  const description = document.getElementById('department-description').value.trim();
  
  if (editIndex !== '') {
    // Edit existing
    const index = parseInt(editIndex);
    if (window.db.departments[index]) {
      window.db.departments[index].name = name;
      window.db.departments[index].description = description;
      saveToStorage();
      renderDepartmentsTable();
      bootstrap.Modal.getInstance(document.getElementById('departmentModal')).hide();
      showToast('Department updated successfully', 'success');
    }
  } else {
    // Add new
    const newId = window.db._counters ? window.db._counters.departmentId++ : (window.db.departments.length + 1);
    if (!window.db._counters) window.db._counters = { departmentId: newId + 1, employeeId: 1, requestId: 1 };
    
    window.db.departments.push({
      id: newId,
      name,
      description
    });
    saveToStorage();
    renderDepartmentsTable();
    bootstrap.Modal.getInstance(document.getElementById('departmentModal')).hide();
    showToast('Department created successfully', 'success');
  }
}

function editDepartment(index) {
  openDepartmentForm(index);
  const modal = new bootstrap.Modal(document.getElementById('departmentModal'));
  modal.show();
}

function deleteDepartment(index) {
  if (confirm('Are you sure you want to delete this department?')) {
    const dept = window.db.departments[index];
    // Remove department from employees
    window.db.employees = window.db.employees.filter(emp => emp.departmentId !== dept.id);
    window.db.departments.splice(index, 1);
    saveToStorage();
    renderDepartmentsTable();
    showToast('Department deleted successfully', 'success');
  }
}

// ============================================
// EMPLOYEES MANAGEMENT (Admin)
// ============================================

function renderEmployeesTable() {
  const container = document.getElementById('employees-table-container');
  if (!container) return;
  
  const employees = window.db.employees;
  
  if (employees.length === 0) {
    container.innerHTML = '<p class="text-muted">No employees found</p>';
    return;
  }
  
  let html = `
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
          <tr>
            <th>ID</th>
            <th>User (Email)</th>
            <th>Position</th>
            <th>Department</th>
            <th>Hire Date</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  employees.forEach((emp, index) => {
    const dept = window.db.departments.find(d => d.id === emp.departmentId);
    const account = window.db.accounts.find(a => a.email === emp.userEmail);
    html += `
      <tr>
        <td>${emp.employeeId}</td>
        <td>${emp.userEmail} ${account ? `(${account.firstName} ${account.lastName})` : ''}</td>
        <td>${emp.position}</td>
        <td>${dept ? dept.name : '—'}</td>
        <td>${emp.hireDate || '—'}</td>
        <td>
          <button class="btn btn-sm btn-primary" onclick="editEmployee(${index})">Edit</button>
          <button class="btn btn-sm btn-danger" onclick="deleteEmployee(${index})">Delete</button>
        </td>
      </tr>
    `;
  });
  
  html += `
        </tbody>
      </table>
    </div>
  `;
  
  container.innerHTML = html;
}

function openEmployeeForm(index = null) {
  const form = document.getElementById('employee-form');
  const editIdInput = document.getElementById('employee-edit-id');
  const deptSelect = document.getElementById('employee-department');
  
  // Populate department dropdown
  deptSelect.innerHTML = '<option value="">Select Department</option>';
  window.db.departments.forEach(dept => {
    deptSelect.innerHTML += `<option value="${dept.id}">${dept.name}</option>`;
  });
  
  form.reset();
  
  if (index !== null) {
    const emp = window.db.employees[index];
    if (emp) {
      editIdInput.value = index;
      document.getElementById('employee-id').value = emp.employeeId;
      document.getElementById('employee-email').value = emp.userEmail;
      document.getElementById('employee-position').value = emp.position;
      document.getElementById('employee-department').value = emp.departmentId;
      document.getElementById('employee-hire-date').value = emp.hireDate || '';
    }
  } else {
    editIdInput.value = '';
  }
}

function saveEmployee() {
  const form = document.getElementById('employee-form');
  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return;
  }
  
  const editIndex = document.getElementById('employee-edit-id').value;
  const employeeId = document.getElementById('employee-id').value.trim();
  const userEmail = document.getElementById('employee-email').value.trim().toLowerCase();
  const position = document.getElementById('employee-position').value.trim();
  const departmentId = parseInt(document.getElementById('employee-department').value);
  const hireDate = document.getElementById('employee-hire-date').value;
  
  // Check if user email exists in accounts
  const account = window.db.accounts.find(acc => acc.email === userEmail);
  if (!account) {
    showToast('User email must match an existing account', 'warning');
    return;
  }
  
  if (editIndex !== '') {
    // Edit existing
    const index = parseInt(editIndex);
    if (window.db.employees[index]) {
      window.db.employees[index].employeeId = employeeId;
      window.db.employees[index].userEmail = userEmail;
      window.db.employees[index].position = position;
      window.db.employees[index].departmentId = departmentId;
      window.db.employees[index].hireDate = hireDate;
      saveToStorage();
      renderEmployeesTable();
      bootstrap.Modal.getInstance(document.getElementById('employeeModal')).hide();
      showToast('Employee updated successfully', 'success');
    }
  } else {
    // Add new - check if employee ID already exists
    if (window.db.employees.find(emp => emp.employeeId === employeeId)) {
      showToast('Employee ID already exists', 'warning');
      return;
    }
    
    window.db.employees.push({
      employeeId,
      userEmail,
      position,
      departmentId,
      hireDate
    });
    saveToStorage();
    renderEmployeesTable();
    bootstrap.Modal.getInstance(document.getElementById('employeeModal')).hide();
    showToast('Employee created successfully', 'success');
  }
}

function editEmployee(index) {
  openEmployeeForm(index);
  const modal = new bootstrap.Modal(document.getElementById('employeeModal'));
  modal.show();
}

function deleteEmployee(index) {
  if (confirm('Are you sure you want to delete this employee?')) {
    window.db.employees.splice(index, 1);
    saveToStorage();
    renderEmployeesTable();
    showToast('Employee deleted successfully', 'success');
  }
}

// ============================================
// REQUESTS MANAGEMENT
// ============================================

function renderRequestsTable() {
  const container = document.getElementById('requests-table-container');
  if (!container) return;
  
  if (!currentUser) return;
  
  // Filter requests by current user (unless admin viewing all)
  let requests = window.db.requests;
  if (currentUser.role !== 'admin') {
    requests = requests.filter(req => req.employeeEmail === currentUser.email);
  }
  
  if (requests.length === 0) {
    container.innerHTML = '<p class="text-muted">No requests found</p>';
    return;
  }
  
  let html = `
    <div class="table-responsive">
      <table class="table table-striped">
        <thead>
          <tr>
            <th>Date</th>
            <th>Type</th>
            <th>Items</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  requests.forEach((req, index) => {
    const statusClass = {
      'Pending': 'warning',
      'Approved': 'success',
      'Rejected': 'danger'
    }[req.status] || 'secondary';
    
    const itemsText = req.items.map(item => `${item.name} (${item.quantity})`).join(', ');
    
    html += `
      <tr>
        <td>${req.date || '—'}</td>
        <td>${req.type}</td>
        <td>${itemsText}</td>
        <td><span class="badge bg-${statusClass}">${req.status}</span></td>
        <td>
          ${currentUser.role === 'admin' ? `
            <button class="btn btn-sm btn-success" onclick="updateRequestStatus(${index}, 'Approved')">Approve</button>
            <button class="btn btn-sm btn-danger" onclick="updateRequestStatus(${index}, 'Rejected')">Reject</button>
          ` : ''}
          <button class="btn btn-sm btn-danger" onclick="deleteRequest(${index})">Delete</button>
        </td>
      </tr>
    `;
  });
  
  html += `
        </tbody>
      </table>
    </div>
  `;
  
  container.innerHTML = html;
}

function openRequestForm() {
  const container = document.getElementById('request-items-container');
  container.innerHTML = `
    <div class="item-row mb-2 d-flex gap-2">
      <input type="text" class="form-control" placeholder="Item name" required>
      <input type="number" class="form-control" placeholder="Quantity" min="1" required style="width: 120px;">
      <button type="button" class="btn btn-danger btn-sm" onclick="removeItemRow(this)">×</button>
    </div>
  `;
  document.getElementById('request-form').reset();
}

function addItemRow() {
  const container = document.getElementById('request-items-container');
  const newRow = document.createElement('div');
  newRow.className = 'item-row mb-2 d-flex gap-2';
  newRow.innerHTML = `
    <input type="text" class="form-control" placeholder="Item name" required>
    <input type="number" class="form-control" placeholder="Quantity" min="1" required style="width: 120px;">
    <button type="button" class="btn btn-danger btn-sm" onclick="removeItemRow(this)">×</button>
  `;
  container.appendChild(newRow);
}

function removeItemRow(btn) {
  const container = document.getElementById('request-items-container');
  if (container.children.length > 1) {
    btn.closest('.item-row').remove();
  } else {
    showToast('At least one item is required', 'warning');
  }
}

function saveRequest() {
  const form = document.getElementById('request-form');
  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return;
  }
  
  if (!currentUser) {
    showToast('Please login to submit requests', 'warning');
    return;
  }
  
  const type = document.getElementById('request-type').value;
  const itemRows = document.querySelectorAll('#request-items-container .item-row');
  
  const items = [];
  let valid = true;
  
  itemRows.forEach(row => {
    const nameInput = row.querySelector('input[type="text"]');
    const qtyInput = row.querySelector('input[type="number"]');
    const name = nameInput.value.trim();
    const quantity = parseInt(qtyInput.value);
    
    if (name && quantity > 0) {
      items.push({ name, quantity });
    } else {
      valid = false;
    }
  });
  
  if (!valid || items.length === 0) {
    showToast('Please fill in all item fields correctly', 'warning');
    return;
  }
  
  const newRequest = {
    type,
    items,
    status: 'Pending',
    date: new Date().toISOString().split('T')[0],
    employeeEmail: currentUser.email
  };
  
  window.db.requests.push(newRequest);
  saveToStorage();
  renderRequestsTable();
  bootstrap.Modal.getInstance(document.getElementById('requestModal')).hide();
  showToast('Request submitted successfully', 'success');
}

function updateRequestStatus(index, status) {
  if (!currentUser || currentUser.role !== 'admin') return;
  
  // Find the request (considering admin might see all requests)
  const request = window.db.requests[index];
  if (request) {
    request.status = status;
    saveToStorage();
    renderRequestsTable();
    showToast(`Request ${status.toLowerCase()}`, 'success');
  }
}

function deleteRequest(index) {
  if (confirm('Are you sure you want to delete this request?')) {
    window.db.requests.splice(index, 1);
    saveToStorage();
    renderRequestsTable();
    showToast('Request deleted successfully', 'success');
  }
}

// ============================================
// TOAST NOTIFICATIONS
// ============================================

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toastId = 'toast-' + Date.now();
  
  const bgClass = {
    'success': 'bg-success',
    'danger': 'bg-danger',
    'warning': 'bg-warning',
    'info': 'bg-info'
  }[type] || 'bg-info';
  
  const toastHTML = `
    <div id="${toastId}" class="toast" role="alert">
      <div class="toast-header ${bgClass} text-white">
        <strong class="me-auto">Notification</strong>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
      </div>
      <div class="toast-body">
        ${message}
      </div>
    </div>
  `;
  
  container.insertAdjacentHTML('beforeend', toastHTML);
  const toastElement = document.getElementById(toastId);
  const toast = new bootstrap.Toast(toastElement, { autohide: true, delay: 3000 });
  toast.show();
  
  // Remove element after it's hidden
  toastElement.addEventListener('hidden.bs.toast', () => {
    toastElement.remove();
  });
}

// ============================================
// INITIALIZATION
// ============================================

function init() {
  // Load data from storage
  loadFromStorage();
  
  // Check authentication
  checkAuthOnLoad();
  
  // Set up routing
  handleRouting();
  window.addEventListener('hashchange', handleRouting);
  
  // Set up event listeners
  document.getElementById('register-form').addEventListener('submit', handleRegister);
  document.getElementById('login-form').addEventListener('submit', handleLogin);
  document.getElementById('logout-btn').addEventListener('click', (e) => {
    e.preventDefault();
    logout();
  });
  document.getElementById('simulate-verify-btn').addEventListener('click', simulateEmailVerification);
  
  // Render verify email page if needed
  if (window.location.hash === '#/verify-email') {
    renderVerifyEmailPage();
  }
  
  // Set initial hash if empty
  if (!window.location.hash || window.location.hash === '#') {
    navigateTo('/');
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
