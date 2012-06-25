using System;
using System.Collections.Generic;
using System.Configuration.Provider;
using System.Linq;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using MongoDB.Driver.Linq;
using MongoMembership.Utils;

namespace MongoMembership.Mongo
{
    internal class MongoGateway : IMongoGateway
    {
        public string MongoConnectionString { get; private set; }

        private MongoDatabase DataBase
        {
            get { return MongoDatabase.Create(this.MongoConnectionString); }
        }
        private MongoCollection<User> UsersCollection
        {
            get { return this.DataBase.GetCollection<User>(typeof(User).Name); }
        }
        private MongoCollection<Role> RolesCollection
        {
            get { return this.DataBase.GetCollection<Role>(typeof(Role).Name); }
        }

        static MongoGateway()
        {
            RegisterClassMapping();
        }

        public MongoGateway(string mongoConnectionString)
        {
            this.MongoConnectionString = mongoConnectionString;
            CreateIndex();
        }

        public void DropUsers()
        {
            this.UsersCollection.Drop();
        }

        public void DropRoles()
        {
            this.RolesCollection.Drop();
        }

        #region User
        public void CreateUser(User user)
        {
            this.UsersCollection.Insert(user);
        }

        public void UpdateUser(User user)
        {
            this.UsersCollection.Save(user);
        }

        public void RemoveUser(User user)
        {
            user.IsDeleted = true;
            UpdateUser(user);
        }

        public User GetById(string id)
        {
            return this.UsersCollection.FindOneById(id);
        }

        public User GetByUserName(string applicationName, string username)
        {
            if (username.IsNullOrWhiteSpace())
                return null;

            try
            {
                return this.UsersCollection
                        .AsQueryable()
                        .Single(user
                            => user.ApplicationName == applicationName
                            && user.Username == username
                            && user.IsDeleted == false);
            }
            catch (Exception ex)
            {
                new ProviderException("Unable to retrieve User information for user '{0}'".F(username), ex);
                return null;
            }
        }

        public User GetByEmail(string applicationName, string email)
        {
            if (this.UsersCollection.Count() == 0)
                return null;

            return this.UsersCollection
                    .AsQueryable()
                    .Single(user
                        => user.ApplicationName == applicationName
                        && user.Email == email
                        && user.IsDeleted == false);
        }

        public IEnumerable<User> GetAllByEmail(string applicationName, string email, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = this.UsersCollection
                        .AsQueryable()
                        .Where(user
                            => user.ApplicationName == applicationName
                            && user.Email.ToLowerInvariant().Contains(email.ToLowerInvariant())
                            && user.IsDeleted == false);

            totalRecords = users.Count();
            return users.Skip(pageIndex * pageSize).Take(pageSize);
        }

        public IEnumerable<User> GetAllByUserName(string applicationName, string username, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = this.UsersCollection
                        .AsQueryable()
                        .Where(user
                            => user.ApplicationName == applicationName
                            && user.Username.ToLowerInvariant().Contains(username.ToLowerInvariant())
                            && user.IsDeleted == false);

            totalRecords = users.Count();
            return users.Skip(pageIndex * pageSize).Take(pageSize);
        }

        public IEnumerable<User> GetAllAnonymByUserName(string applicationName, string username, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = this.UsersCollection
                .AsQueryable()
                .Where(user
                    => user.ApplicationName == applicationName
                    && user.Username.ToLowerInvariant().Contains(username.ToLowerInvariant())
                    && user.IsAnonymous
                    && user.IsDeleted == false);

            totalRecords = users.Count();
            return users.Skip(pageIndex * pageSize).Take(pageSize);
        }

        public IEnumerable<User> GetAll(string applicationName, int pageIndex, int pageSize, out int totalRecords)
        {
            totalRecords = (int)this.UsersCollection.Count();
            return this.UsersCollection
                    .AsQueryable()
                    .Where(user
                        => user.ApplicationName == applicationName
                        && user.IsDeleted == false)
                    .Skip(pageIndex * pageSize)
                    .Take(pageSize);
        }

        public IEnumerable<User> GetAllAnonym(string applicationName, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = this.UsersCollection
                .AsQueryable()
                .Where(user
                    => user.ApplicationName == applicationName
                    && user.IsAnonymous
                    && user.IsDeleted == false);

            totalRecords = users.Count();
            return users.Skip(pageIndex * pageSize).Take(pageSize);
        }

        public IEnumerable<User> GetAllInactiveSince(string applicationName, DateTime inactiveDate, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = this.UsersCollection
                        .AsQueryable()
                        .Where(user
                            => user.ApplicationName == applicationName
                            && user.LastActivityDate <= inactiveDate
                            && user.IsDeleted == false);
            totalRecords = users.Count();
            return users
                    .Skip(pageIndex * pageSize)
                    .Take(pageSize);
        }

        public IEnumerable<User> GetAllInactiveAnonymSince(string applicationName, DateTime inactiveDate, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = this.UsersCollection
                        .AsQueryable()
                        .Where(user
                            => user.ApplicationName == applicationName
                            && user.LastActivityDate <= inactiveDate
                            && user.IsAnonymous
                            && user.IsDeleted == false);
            totalRecords = users.Count();
            return users
                    .Skip(pageIndex * pageSize)
                    .Take(pageSize);
        }

        public IEnumerable<User> GetInactiveSinceByUserName(string applicationName, string username, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = this.UsersCollection
                        .AsQueryable()
                        .Where(user
                            => user.ApplicationName == applicationName
                            && user.Username.ToLowerInvariant().Contains(username.ToLowerInvariant())
                            && user.LastActivityDate <= userInactiveSinceDate
                            && user.IsDeleted == false);
            totalRecords = users.Count();
            return users
                    .Skip(pageIndex * pageSize)
                    .Take(pageSize);
        }

        public IEnumerable<User> GetInactiveAnonymSinceByUserName(string applicationName, string username, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = this.UsersCollection
                        .AsQueryable()
                        .Where(user
                            => user.ApplicationName == applicationName
                            && user.Username.ToLowerInvariant().Contains(username.ToLowerInvariant())
                            && user.LastActivityDate <= userInactiveSinceDate
                            && user.IsAnonymous
                            && user.IsDeleted == false);
            totalRecords = users.Count();
            return users
                    .Skip(pageIndex * pageSize)
                    .Take(pageSize);
        }

        public int GetUserForPeriodOfTime(string applicationName, TimeSpan timeSpan)
        {
            return this.UsersCollection
                    .AsQueryable()
                    .Count(user
                        => user.ApplicationName == applicationName
                        && user.LastActivityDate > DateTime.UtcNow.Subtract(timeSpan));
        }
        #endregion

        #region Role
        public void CreateRole(Role role)
        {
            this.RolesCollection.Insert(role);
        }

        public void RemoveRole(string applicationName, string roleName)
        {
            var query = new QueryDocument
            {
                new Dictionary<string, object>
                {
                    {Util.GetElementNameFor<Role>(_ => _.ApplicationName), applicationName},
                    {Util.GetElementNameFor<Role>(_ => _.RoleName), roleName}
                }
            };

            this.RolesCollection.Remove(query);
        }

        public string[] GetAllRoles(string applicationName)
        {
            return this.RolesCollection
                    .AsQueryable()
                    .Where(role => role.ApplicationName == applicationName)
                    .Select(role => role.RoleName)
                    .ToArray();
        }

        public string[] GetRolesForUser(string applicationName, string username)
        {
            if (username.IsNullOrWhiteSpace())
                return null;

            var roles = this.UsersCollection
                        .AsQueryable()
                        .Single(user
                            => user.ApplicationName == applicationName
                            && user.Username == username)
                        .Roles;

            return roles == null ? null : roles.ToArray();
        }

        public string[] GetUsersInRole(string applicationName, string roleName)
        {
            return this.UsersCollection
                    .AsQueryable()
                    .Where(user
                        => user.ApplicationName == applicationName
                        && user.Roles.Contains(roleName))
                    .Select(user => user.Username)
                    .ToArray();
        }

        public bool IsUserInRole(string applicationName, string username, string roleName)
        {
            return UsersCollection
                    .AsQueryable()
                    .Any(user
                        => user.ApplicationName == applicationName
                        && user.Username == username
                        && user.Roles.Contains(roleName));
        }

        public bool IsRoleExists(string applicationName, string roleName)
        {
            return this.RolesCollection
                    .AsQueryable()
                    .Any(role
                        => role.ApplicationName == applicationName
                        && role.RoleName == roleName);
        }
        #endregion

        #region Private Methods
        private static void RegisterClassMapping()
        {
            if (!BsonClassMap.IsClassMapRegistered(typeof(User)))
            {
                // Initialize Mongo Mappings
                BsonClassMap.RegisterClassMap<User>(cm =>
                {
                    cm.AutoMap();
                    cm.SetIgnoreExtraElements(true);
                    cm.SetIsRootClass(true);
                    cm.MapIdField(c => c.Id);
                    cm.MapProperty(c => c.ApplicationName).SetElementName("ApplicationName");
                    cm.MapProperty(c => c.Username).SetElementName("Username");
                    cm.MapProperty(c => c.Comment).SetElementName("Comment");
                    cm.MapProperty(c => c.CreateDate).SetElementName("CreateDate");
                    cm.MapProperty(c => c.Email).SetElementName("Email");
                    cm.MapProperty(c => c.FailedPasswordAnswerAttemptCount).SetElementName("FailedPasswordAnswerAttemptCount");
                    cm.MapProperty(c => c.FailedPasswordAttemptCount).SetElementName("FailedPasswordAttemptCount");
                    cm.MapProperty(c => c.FailedPasswordAnswerAttemptWindowStart).SetElementName("FailedPasswordAnswerAttemptWindowStart");
                    cm.MapProperty(c => c.FailedPasswordAttemptWindowStart).SetElementName("FailedPasswordAttemptWindowStart");
                    cm.MapProperty(c => c.IsApproved).SetElementName("IsApproved");
                    cm.MapProperty(c => c.IsDeleted).SetElementName("IsDeleted");
                    cm.MapProperty(c => c.IsLockedOut).SetElementName("IsLockedOut");
                    cm.MapProperty(c => c.LastActivityDate).SetElementName("LastActivityDate");
                    cm.MapProperty(c => c.LastLockedOutDate).SetElementName("LastLockedOutDate");
                    cm.MapProperty(c => c.LastLoginDate).SetElementName("LastLoginDate");
                    cm.MapProperty(c => c.LastPasswordChangedDate).SetElementName("LastPasswordChangedDate");
                    cm.MapProperty(c => c.Password).SetElementName("Password");
                    cm.MapProperty(c => c.PasswordAnswer).SetElementName("PasswordAnswer");
                    cm.MapProperty(c => c.PasswordQuestion).SetElementName("PasswordQuestion");
                    cm.MapProperty(c => c.PasswordSalt).SetElementName("PasswordSalt");
                    cm.MapProperty(c => c.Roles).SetElementName("Roles").SetIgnoreIfNull(true);
                });
            }

            if (!BsonClassMap.IsClassMapRegistered(typeof(Role)))
            {
                BsonClassMap.RegisterClassMap<Role>(cm =>
                {
                    cm.AutoMap();
                    cm.SetIgnoreExtraElements(true);
                    cm.SetIsRootClass(true);
                    cm.MapProperty(c => c.ApplicationName).SetElementName("ApplicationName");
                    cm.MapProperty(c => c.RoleName).SetElementName("RoleName");
                });
            }
        }

        private void CreateIndex()
        {
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.Email));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.Username));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.Roles));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.Roles), Util.GetElementNameFor<User>(_ => _.Username));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.IsAnonymous));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.IsAnonymous), Util.GetElementNameFor<User>(_ => _.LastActivityDate));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.IsAnonymous), Util.GetElementNameFor<User>(_ => _.LastActivityDate), Util.GetElementNameFor<User>(_ => _.Username));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.IsAnonymous), Util.GetElementNameFor<User>(_ => _.Username));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.Username), Util.GetElementNameFor<User>(_ => _.IsAnonymous));
            this.UsersCollection.EnsureIndex(Util.GetElementNameFor<User>(_ => _.ApplicationName), Util.GetElementNameFor<User>(_ => _.LastActivityDate));

            this.RolesCollection.EnsureIndex(Util.GetElementNameFor<Role>(_ => _.ApplicationName));
            this.RolesCollection.EnsureIndex(Util.GetElementNameFor<Role>(_ => _.ApplicationName), Util.GetElementNameFor<Role>(_ => _.RoleName));
        }
        #endregion
    }
}