/**
 * TypeScript Sample File for Theme Testing
 * This file demonstrates TypeScript-specific syntax highlighting features
 */

// Type definitions
type UserRole = 'admin' | 'user' | 'guest';
type Status = 'active' | 'inactive' | 'pending';

interface User {
    readonly id: number;
    name: string;
    email: string;
    role: UserRole;
    status: Status;
    preferences?: UserPreferences;
    createdAt: Date;
}

interface UserPreferences {
    theme: 'light' | 'dark';
    notifications: boolean;
    language: string;
}

// Generic interface
interface ApiResponse<T> {
    data: T;
    success: boolean;
    message: string;
    timestamp: number;
}

interface PaginatedResponse<T> extends ApiResponse<T[]> {
    totalCount: number;
    pageSize: number;
    currentPage: number;
}

// Enum
enum HttpStatus {
    OK = 200,
    CREATED = 201,
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    NOT_FOUND = 404,
    INTERNAL_SERVER_ERROR = 500
}

// Abstract class
abstract class BaseService<T> {
    protected abstract apiEndpoint: string;

    abstract create(item: Omit<T, 'id'>): Promise<T>;
    abstract getById(id: number): Promise<T | null>;
    abstract update(id: number, updates: Partial<T>): Promise<T>;
    abstract delete(id: number): Promise<boolean>;

    protected handleError(error: unknown): never {
        if (error instanceof Error) {
            throw new Error(`Service error: ${error.message}`);
        }
        throw new Error('Unknown service error');
    }
}

// Class with generics and decorators
class UserService extends BaseService<User> {
    protected apiEndpoint = '/api/users';
    private cache = new Map<number, User>();

    // Method overloads
    async getUsers(): Promise<User[]>;
    async getUsers(role: UserRole): Promise<User[]>;
    async getUsers(role: UserRole, status: Status): Promise<User[]>;
    async getUsers(role?: UserRole, status?: Status): Promise<User[]> {
        try {
            const params = new URLSearchParams();
            if (role) params.append('role', role);
            if (status) params.append('status', status);

            const response = await fetch(`${this.apiEndpoint}?${params}`);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result: PaginatedResponse<User> = await response.json();
            return result.data;
        } catch (error) {
            this.handleError(error);
        }
    }

    async create(userData: Omit<User, 'id' | 'createdAt'>): Promise<User> {
        const user: User = {
            ...userData,
            id: Date.now(),
            createdAt: new Date()
        };

        this.cache.set(user.id, user);
        return user;
    }

    async getById(id: number): Promise<User | null> {
        if (this.cache.has(id)) {
            return this.cache.get(id)!;
        }
        
        try {
            const response = await fetch(`${this.apiEndpoint}/${id}`);
            if (response.status === HttpStatus.NOT_FOUND) {
                return null;
            }
            
            const result: ApiResponse<User> = await response.json();
            this.cache.set(id, result.data);
            return result.data;
        } catch (error) {
            this.handleError(error);
        }
    }

    async update(id: number, updates: Partial<User>): Promise<User> {
        const existingUser = await this.getById(id);
        if (!existingUser) {
            throw new Error(`User with id ${id} not found`);
        }

        const updatedUser: User = { ...existingUser, ...updates };
        this.cache.set(id, updatedUser);
        return updatedUser;
    }

    async delete(id: number): Promise<boolean> {
        const exists = this.cache.has(id) || (await this.getById(id)) !== null;
        if (exists) {
            this.cache.delete(id);
            return true;
        }
        return false;
    }
}

// Utility types and functions
type UserKeys = keyof User;
type CreateUserRequest = Pick<User, 'name' | 'email' | 'role'>;
type UpdateUserRequest = Partial<Pick<User, 'name' | 'email' | 'status' | 'preferences'>>;

// Generic function with constraints
function processUsers<T extends User>(
    users: T[],
    predicate: (user: T) => boolean
): T[] {
    return users.filter(predicate);
}

// Function with conditional types
function formatUserData<T extends boolean>(
    user: User,
    includeId: T
): T extends true ? User : Omit<User, 'id'> {
    if (includeId) {
        return user as any;
    }
    const { id, ...userWithoutId } = user;
    return userWithoutId as any;
}

// Namespace
namespace UserUtils {
    export function isAdmin(user: User): boolean {
        return user.role === 'admin';
    }

    export function getDisplayName(user: User): string {
        return user.name || user.email.split('@')[0];
    }

    export const DEFAULT_PREFERENCES: UserPreferences = {
        theme: 'light',
        notifications: true,
        language: 'en'
    };
}

// Module augmentation example
declare global {
    interface Window {
        userService: UserService;
    }
}

// Export types and implementation
export type { User, UserRole, Status, UserPreferences, ApiResponse };
export { HttpStatus, UserService, UserUtils, processUsers, formatUserData };