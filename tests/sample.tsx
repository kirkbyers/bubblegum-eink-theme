/**
 * React TSX Sample File for Theme Testing
 * This file demonstrates React/JSX syntax highlighting with TypeScript
 */

import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { User, UserService } from './sample';

// Props interfaces
interface UserCardProps {
    user: User;
    onEdit?: (user: User) => void;
    onDelete?: (userId: number) => void;
    className?: string;
}

interface UserListProps {
    users: User[];
    loading?: boolean;
    error?: string | null;
    onUserSelect: (user: User) => void;
}

interface FormData {
    name: string;
    email: string;
    role: 'admin' | 'user' | 'guest';
}

// Custom hook
function useUsers() {
    const [users, setUsers] = useState<User[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const userService = useRef(new UserService());

    const fetchUsers = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const userData = await userService.current.getUsers();
            setUsers(userData);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to fetch users');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchUsers();
    }, [fetchUsers]);

    return { users, loading, error, refetch: fetchUsers };
}

// Functional component with props destructuring
const UserCard: React.FC<UserCardProps> = ({ 
    user, 
    onEdit, 
    onDelete, 
    className = '' 
}) => {
    const handleEdit = useCallback(() => {
        onEdit?.(user);
    }, [user, onEdit]);

    const handleDelete = useCallback(() => {
        if (window.confirm(`Are you sure you want to delete ${user.name}?`)) {
            onDelete?.(user.id);
        }
    }, [user.id, user.name, onDelete]);

    const statusColor = useMemo(() => {
        switch (user.status) {
            case 'active':
                return 'green';
            case 'inactive':
                return 'red';
            case 'pending':
                return 'orange';
            default:
                return 'gray';
        }
    }, [user.status]);

    return (
        <div className={`user-card ${className}`} data-testid="user-card">
            <div className="user-header">
                <h3>{user.name}</h3>
                <span 
                    className={`status status-${user.status}`}
                    style={{ color: statusColor }}
                >
                    {user.status.toUpperCase()}
                </span>
            </div>
            
            <div className="user-details">
                <p><strong>Email:</strong> {user.email}</p>
                <p><strong>Role:</strong> {user.role}</p>
                <p><strong>Created:</strong> {user.createdAt.toLocaleDateString()}</p>
                
                {user.preferences && (
                    <div className="preferences">
                        <h4>Preferences</h4>
                        <ul>
                            <li>Theme: {user.preferences.theme}</li>
                            <li>Notifications: {user.preferences.notifications ? 'On' : 'Off'}</li>
                            <li>Language: {user.preferences.language}</li>
                        </ul>
                    </div>
                )}
            </div>

            <div className="user-actions">
                <button 
                    onClick={handleEdit}
                    className="btn btn-primary"
                    aria-label={`Edit ${user.name}`}
                >
                    Edit
                </button>
                <button 
                    onClick={handleDelete}
                    className="btn btn-danger"
                    aria-label={`Delete ${user.name}`}
                >
                    Delete
                </button>
            </div>
        </div>
    );
};

// Component with conditional rendering and fragments
const UserList: React.FC<UserListProps> = ({ 
    users, 
    loading = false, 
    error = null, 
    onUserSelect 
}) => {
    if (loading) {
        return (
            <div className="loading-spinner" role="status" aria-live="polite">
                <span>Loading users...</span>
            </div>
        );
    }

    if (error) {
        return (
            <div className="error-message" role="alert">
                <h3>Error</h3>
                <p>{error}</p>
                <button onClick={() => window.location.reload()}>
                    Retry
                </button>
            </div>
        );
    }

    if (users.length === 0) {
        return (
            <div className="empty-state">
                <h3>No Users Found</h3>
                <p>There are no users to display at this time.</p>
            </div>
        );
    }

    return (
        <div className="user-list">
            <h2>Users ({users.length})</h2>
            <div className="user-grid">
                {users.map((user) => (
                    <UserCard
                        key={user.id}
                        user={user}
                        onEdit={onUserSelect}
                        className="user-grid-item"
                    />
                ))}
            </div>
        </div>
    );
};

// Main application component with hooks and state management
const UserManagementApp: React.FC = () => {
    const { users, loading, error, refetch } = useUsers();
    const [selectedUser, setSelectedUser] = useState<User | null>(null);
    const [showForm, setShowForm] = useState(false);
    const [formData, setFormData] = useState<FormData>({
        name: '',
        email: '',
        role: 'user'
    });

    const handleUserSelect = useCallback((user: User) => {
        setSelectedUser(user);
        setFormData({
            name: user.name,
            email: user.email,
            role: user.role
        });
        setShowForm(true);
    }, []);

    const handleFormSubmit = useCallback(async (e: React.FormEvent) => {
        e.preventDefault();
        
        try {
            if (selectedUser) {
                // Update existing user
                console.log('Updating user:', selectedUser.id, formData);
            } else {
                // Create new user
                console.log('Creating new user:', formData);
            }
            
            setShowForm(false);
            setSelectedUser(null);
            setFormData({ name: '', email: '', role: 'user' });
            await refetch();
        } catch (err) {
            console.error('Form submission failed:', err);
        }
    }, [selectedUser, formData, refetch]);

    const handleInputChange = useCallback((
        e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
    ) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
    }, []);

    return (
        <div className="app">
            <header className="app-header">
                <h1>User Management System</h1>
                <button 
                    onClick={() => setShowForm(true)}
                    className="btn btn-success"
                >
                    Add New User
                </button>
            </header>

            <main className="app-main">
                <UserList 
                    users={users}
                    loading={loading}
                    error={error}
                    onUserSelect={handleUserSelect}
                />

                {showForm && (
                    <div className="modal-overlay" onClick={() => setShowForm(false)}>
                        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                            <form onSubmit={handleFormSubmit}>
                                <h2>{selectedUser ? 'Edit User' : 'Add New User'}</h2>
                                
                                <div className="form-group">
                                    <label htmlFor="name">Name:</label>
                                    <input
                                        type="text"
                                        id="name"
                                        name="name"
                                        value={formData.name}
                                        onChange={handleInputChange}
                                        required
                                    />
                                </div>

                                <div className="form-group">
                                    <label htmlFor="email">Email:</label>
                                    <input
                                        type="email"
                                        id="email"
                                        name="email"
                                        value={formData.email}
                                        onChange={handleInputChange}
                                        required
                                    />
                                </div>

                                <div className="form-group">
                                    <label htmlFor="role">Role:</label>
                                    <select
                                        id="role"
                                        name="role"
                                        value={formData.role}
                                        onChange={handleInputChange}
                                    >
                                        <option value="user">User</option>
                                        <option value="admin">Admin</option>
                                        <option value="guest">Guest</option>
                                    </select>
                                </div>

                                <div className="form-actions">
                                    <button type="submit" className="btn btn-primary">
                                        {selectedUser ? 'Update' : 'Create'}
                                    </button>
                                    <button 
                                        type="button" 
                                        onClick={() => setShowForm(false)}
                                        className="btn btn-secondary"
                                    >
                                        Cancel
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
};

export default UserManagementApp;
export { UserCard, UserList, useUsers };