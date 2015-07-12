using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using MongoMembership.Utils;

namespace MongoMembership.Mongo
{
    internal interface IMongoGateway
    {
        void DropUsers();
        void DropRoles();
        void CreateUser(User user);
        void UpdateUser(User user);
        void RemoveUser(User user);
        Task<User> GetById(string id);
        Task<User> GetByUserName(string applicationName, string username);
        Task<User> GetByEmail(string applicationName, string email);
        Task<ReturnResult> GetAllByEmail(string applicationName, string email, int pageIndex, int pageSize);
        Task<ReturnResult> GetAllByUserName(string applicationName, string username, int pageIndex, int pageSize);
        Task<ReturnResult> GetAllAnonymByUserName(string applicationName, string username, int pageIndex, int pageSize);
        Task<ReturnResult> GetAll(string applicationName, int pageIndex, int pageSize);
        Task<ReturnResult> GetAllAnonym(string applicationName, int pageIndex, int pageSize);
        Task<ReturnResult> GetAllInactiveSince(string applicationName, DateTime inactiveDate, int pageIndex, int pageSize);
        Task<ReturnResult> GetAllInactiveAnonymSince(string applicationName, DateTime inactiveDate, int pageIndex, int pageSize);
        Task<ReturnResult> GetInactiveSinceByUserName(string applicationName, string username, DateTime userInactiveSinceDate, int pageIndex, int pageSize);
        Task<ReturnResult> GetInactiveAnonymSinceByUserName(string applicationName, string username, DateTime userInactiveSinceDate, int pageIndex, int pageSize);
        Task<long> GetUserForPeriodOfTime(string applicationName, TimeSpan timeSpan);
        void CreateRole(Role role);
        void RemoveRole(string applicationName, string roleName);
        Task<string[]> GetAllRoles(string applicationName);
        Task<string[]> GetRolesForUser(string applicationName, string username);
        Task<string[]> GetUsersInRole(string applicationName, string roleName);
        Task<bool> IsUserInRole(string applicationName, string username, string roleName);
        Task<bool> IsRoleExists(string applicationName, string roleName);
        Task<long> UserCount();
    }
}