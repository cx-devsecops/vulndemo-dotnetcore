using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using Verademo.Commands;
using Xunit;

namespace Verademo.Tests.Commands
{
    /// <summary>
    /// Tests for IgnoreCommand verifying that the second-order SQL injection vulnerability
    /// (CWE-89) has been fully remediated via parameterized queries.
    ///
    /// The vulnerable code previously:
    ///   1. Fetched blab_name with a string-concatenated SELECT.
    ///   2. Embedded the DB-returned blab_name (plus usernames) directly into an INSERT
    ///      using string concatenation, enabling second-order SQL injection.
    ///
    /// The fix uses parameterized placeholders (@param) for every user-controlled or
    /// DB-sourced value so that no untrusted data ever appears in the SQL command text.
    /// </summary>
    public class IgnoreCommandTests
    {
        // ── Test cases ─────────────────────────────────────────────────────────────

        /// <summary>
        /// The SELECT query must use a parameter placeholder for blabberUsername, not embed
        /// the raw value in the SQL string.
        /// </summary>
        [Fact]
        public void Execute_SelectQuery_UsesParameterizedQuery()
        {
            // Arrange
            var conn = new SequentialFakeConnection(
                new FakeDbCommand(nonQueryResult: 1),          // DELETE
                new FakeDbCommand(scalarResult: "SafeBlab"),   // SELECT
                new FakeDbCommand(nonQueryResult: 1)           // INSERT
            );
            var cmd = new IgnoreCommand(conn, "testuser");

            // Act
            cmd.Execute("targetuser");

            var selectCmd = conn.Commands[1];

            // Assert: SQL text uses a placeholder, not the raw username
            Assert.DoesNotContain("targetuser", selectCmd.CommandText, StringComparison.Ordinal);
            Assert.Contains("@", selectCmd.CommandText, StringComparison.Ordinal);

            // The value must be bound as a parameter
            Assert.True(
                selectCmd.CapturedParameters.Any(p => p.Value?.ToString() == "targetuser"),
                "SELECT must bind blabberUsername as a parameter."
            );
        }

        /// <summary>
        /// The INSERT query must use parameter placeholders for all values; no raw user data
        /// or DB-sourced value should appear literally in the SQL command text.
        /// This directly tests the second-order injection sink.
        /// </summary>
        [Fact]
        public void Execute_InsertQuery_UsesParameterizedQuery()
        {
            // Arrange
            var conn = new SequentialFakeConnection(
                new FakeDbCommand(nonQueryResult: 1),
                new FakeDbCommand(scalarResult: "SafeBlab"),
                new FakeDbCommand(nonQueryResult: 1)
            );
            var cmd = new IgnoreCommand(conn, "listeneruser");

            // Act
            cmd.Execute("blabberuser");

            var insertCmd = conn.Commands[2];

            // Assert: raw usernames must NOT appear in the SQL text
            Assert.DoesNotContain("listeneruser", insertCmd.CommandText, StringComparison.Ordinal);
            Assert.DoesNotContain("blabberuser", insertCmd.CommandText, StringComparison.Ordinal);
            Assert.DoesNotContain("SafeBlab", insertCmd.CommandText, StringComparison.Ordinal);
            Assert.Contains("@", insertCmd.CommandText, StringComparison.Ordinal);

            // Listener username must be bound as a parameter
            Assert.True(
                insertCmd.CapturedParameters.Any(p => p.Value?.ToString() == "listeneruser"),
                "INSERT must bind the listener username as a parameter."
            );
        }

        /// <summary>
        /// Simulates the second-order attack: a malicious payload stored in the DB is returned
        /// by the SELECT and then used in the INSERT.  With parameterization the payload must
        /// remain in a parameter value (safe) and must NOT appear in the SQL command text.
        /// </summary>
        [Fact]
        public void Execute_WithSqlInjectionPayloadStoredInDatabase_InsertSqlIsNotInjected()
        {
            // Arrange – malicious value that would have been previously written to the DB
            const string maliciousBlabName = "x\"); DROP TABLE users_history; --";

            var conn = new SequentialFakeConnection(
                new FakeDbCommand(nonQueryResult: 1),
                new FakeDbCommand(scalarResult: maliciousBlabName),  // DB returns attacker payload
                new FakeDbCommand(nonQueryResult: 1)
            );
            var cmd = new IgnoreCommand(conn, "victim");

            // Act – must complete without throwing
            cmd.Execute("attacker");

            var insertCmd = conn.Commands[2];

            // Assert: destructive SQL keywords must not appear in the command text
            Assert.DoesNotContain("DROP TABLE", insertCmd.CommandText, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("--", insertCmd.CommandText, StringComparison.Ordinal);
            Assert.Contains("@", insertCmd.CommandText, StringComparison.Ordinal);

            // The dangerous value must be carried safely in a bound parameter
            var eventParam = insertCmd.CapturedParameters
                .FirstOrDefault(p => p.Value?.ToString()?.Contains("DROP TABLE",
                    StringComparison.OrdinalIgnoreCase) == true);
            Assert.NotNull(eventParam);
        }

        /// <summary>
        /// A classic OR-based payload in blabberUsername must not appear verbatim in the
        /// SELECT SQL text; it must be bound as a parameter.
        /// </summary>
        [Fact]
        public void Execute_WithOrInjectionPayloadInBlabberUsername_SelectQueryIsParameterized()
        {
            // Arrange
            const string maliciousUsername = "' OR '1'='1";

            var conn = new SequentialFakeConnection(
                new FakeDbCommand(nonQueryResult: 1),
                new FakeDbCommand(scalarResult: "NormalBlab"),
                new FakeDbCommand(nonQueryResult: 1)
            );
            var cmd = new IgnoreCommand(conn, "user1");

            // Act
            cmd.Execute(maliciousUsername);

            var selectCmd = conn.Commands[1];

            // Assert: the injection payload must not be in the SQL text
            Assert.DoesNotContain(maliciousUsername, selectCmd.CommandText, StringComparison.Ordinal);

            // Must be a bound parameter
            Assert.True(
                selectCmd.CapturedParameters.Any(p => p.Value?.ToString() == maliciousUsername),
                "The malicious blabberUsername must be bound as a parameter in the SELECT query."
            );
        }

        /// <summary>
        /// Verifies that the pre-existing DELETE query (which was already parameterized) still
        /// uses parameter placeholders after the refactor.
        /// </summary>
        [Fact]
        public void Execute_DeleteQuery_UsesParameterizedQuery()
        {
            // Arrange
            var conn = new SequentialFakeConnection(
                new FakeDbCommand(nonQueryResult: 1),
                new FakeDbCommand(scalarResult: "SomeBlab"),
                new FakeDbCommand(nonQueryResult: 1)
            );
            var cmd = new IgnoreCommand(conn, "myuser");

            // Act
            cmd.Execute("otheruser");

            var deleteCmd = conn.Commands[0];

            // Assert: SQL text uses placeholders, not raw values
            Assert.DoesNotContain("myuser", deleteCmd.CommandText, StringComparison.Ordinal);
            Assert.DoesNotContain("otheruser", deleteCmd.CommandText, StringComparison.Ordinal);
            Assert.Contains("@", deleteCmd.CommandText, StringComparison.Ordinal);

            Assert.True(
                deleteCmd.CapturedParameters.Any(p => p.Value?.ToString() == "otheruser"),
                "DELETE must bind blabberUsername as a parameter."
            );
            Assert.True(
                deleteCmd.CapturedParameters.Any(p => p.Value?.ToString() == "myuser"),
                "DELETE must bind username as a parameter."
            );
        }

        /// <summary>
        /// Verifies that Execute completes successfully under normal (non-attack) conditions,
        /// confirming that the parameterization fix did not break the happy path.
        /// </summary>
        [Fact]
        public void Execute_NormalInput_CompletesSuccessfully()
        {
            // Arrange
            var conn = new SequentialFakeConnection(
                new FakeDbCommand(nonQueryResult: 1),
                new FakeDbCommand(scalarResult: "Alice's Blab"),
                new FakeDbCommand(nonQueryResult: 1)
            );
            var cmd = new IgnoreCommand(conn, "alice");

            // Act – must not throw
            var ex = Record.Exception(() => cmd.Execute("bob"));

            // Assert
            Assert.Null(ex);

            // All three commands must have been created and executed
            Assert.Equal(3, conn.Commands.Count);
        }
    }

    // ── Fake infrastructure ────────────────────────────────────────────────────

    /// <summary>
    /// A concrete <see cref="DbConnection"/> that returns pre-built <see cref="FakeDbCommand"/>
    /// instances in the order they were provided.
    /// </summary>
    internal sealed class SequentialFakeConnection : DbConnection
    {
        private readonly FakeDbCommand[] _commands;
        private int _index;

        public IReadOnlyList<FakeDbCommand> Commands => _commands;

        public SequentialFakeConnection(params FakeDbCommand[] commands)
        {
            _commands = commands;
        }

        protected override DbCommand CreateDbCommand() =>
            _commands[Math.Min(_index++, _commands.Length - 1)];

        // Minimal overrides – not exercised by IgnoreCommand
        public override string ConnectionString { get; set; } = string.Empty;
        public override string Database => string.Empty;
        public override string DataSource => string.Empty;
        public override string ServerVersion => string.Empty;
        public override ConnectionState State => ConnectionState.Open;
        public override void ChangeDatabase(string databaseName) { }
        public override void Close() { }
        public override void Open() { }
        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) =>
            throw new NotImplementedException();
    }

    /// <summary>
    /// A concrete <see cref="DbCommand"/> that records the SQL text it is assigned and
    /// every parameter added to it, without touching a real database.
    /// </summary>
    internal sealed class FakeDbCommand : DbCommand
    {
        private readonly int _nonQueryResult;
        private readonly object? _scalarResult;
        private readonly FakeParameterCollection _paramCollection = new();

        /// <summary>Parameters that were bound to this command via <c>Parameters.Add()</c>.</summary>
        public IReadOnlyList<DbParameter> CapturedParameters => _paramCollection.Items;

        public FakeDbCommand(int nonQueryResult = 1, object? scalarResult = null)
        {
            _nonQueryResult = nonQueryResult;
            _scalarResult = scalarResult;
        }

        public override string CommandText { get; set; } = string.Empty;
        public override int CommandTimeout { get; set; }
        public override CommandType CommandType { get; set; }
        public override bool DesignTimeVisible { get; set; }
        public override UpdateRowSource UpdatedRowSource { get; set; }

        protected override DbConnection? DbConnection { get; set; }
        protected override DbTransaction? DbTransaction { get; set; }
        protected override DbParameterCollection DbParameterCollection => _paramCollection;

        public override void Cancel() { }
        public override int ExecuteNonQuery() => _nonQueryResult;
        public override object? ExecuteScalar() => _scalarResult;
        public override void Prepare() { }

        protected override DbParameter CreateDbParameter() => new SqlParameter();
        protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) =>
            throw new NotImplementedException();
    }

    /// <summary>
    /// A minimal <see cref="DbParameterCollection"/> backed by a plain list.
    /// </summary>
    internal sealed class FakeParameterCollection : DbParameterCollection
    {
        private readonly List<DbParameter> _list = new();

        public IReadOnlyList<DbParameter> Items => _list;

        public override int Count => _list.Count;
        public override object SyncRoot => ((System.Collections.ICollection)_list).SyncRoot;

        public override int Add(object value)
        {
            _list.Add((DbParameter)value);
            return _list.Count - 1;
        }

        public override void AddRange(Array values)
        {
            foreach (object v in values) Add(v);
        }

        public override void Clear() => _list.Clear();
        public override bool Contains(object value) => _list.Contains((DbParameter)value);
        public override bool Contains(string value) => _list.Any(p => p.ParameterName == value);
        public override void CopyTo(Array array, int index) =>
            ((System.Collections.ICollection)_list).CopyTo(array, index);
        public override System.Collections.IEnumerator GetEnumerator() => _list.GetEnumerator();
        public override int IndexOf(object value) => _list.IndexOf((DbParameter)value);
        public override int IndexOf(string parameterName) =>
            _list.FindIndex(p => p.ParameterName == parameterName);
        public override void Insert(int index, object value) => _list.Insert(index, (DbParameter)value);
        public override void Remove(object value) => _list.Remove((DbParameter)value);
        public override void RemoveAt(int index) => _list.RemoveAt(index);
        public override void RemoveAt(string parameterName)
        {
            int i = IndexOf(parameterName);
            if (i >= 0) _list.RemoveAt(i);
        }

        protected override DbParameter GetParameter(int index) => _list[index];
        protected override DbParameter GetParameter(string parameterName) =>
            _list.First(p => p.ParameterName == parameterName);
        protected override void SetParameter(int index, DbParameter value) => _list[index] = value;
        protected override void SetParameter(string parameterName, DbParameter value)
        {
            int i = IndexOf(parameterName);
            if (i >= 0) _list[i] = value;
        }
    }
}
