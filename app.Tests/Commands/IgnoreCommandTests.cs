using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using Moq;
using Verademo.Commands;
using Xunit;

namespace Verademo.Tests.Commands
{
    /// <summary>
    /// Tests for IgnoreCommand to verify SQL injection remediation.
    ///
    /// The vulnerability (CWE-89) was: blabberUsername was concatenated directly into
    /// SQL queries without parameterization. The fix replaces string concatenation with
    /// parameterized queries using SqlParameter objects for all SQL statements.
    /// </summary>
    public class IgnoreCommandTests
    {
        // -----------------------------------------------------------------------
        // Helper infrastructure: fake DbConnection / DbCommand that capture
        // the parameters added to each command so tests can assert them.
        // -----------------------------------------------------------------------

        private class CapturedCommand
        {
            public string CommandText { get; set; } = string.Empty;
            public List<(string Name, object Value)> Parameters { get; } = new();
        }

        /// <summary>
        /// Minimal fake DbCommand that records CommandText and parameters
        /// without requiring a real database connection.
        /// </summary>
        private class FakeDbCommand : DbCommand
        {
            public CapturedCommand Captured { get; } = new CapturedCommand();
            private readonly FakeDbParameterCollection _params = new();

            public override string CommandText
            {
                get => Captured.CommandText;
                set => Captured.CommandText = value;
            }
            public override int CommandTimeout { get; set; }
            public override CommandType CommandType { get; set; }
            public override bool DesignTimeVisible { get; set; }
            public override UpdateRowSource UpdatedRowSource { get; set; }
            protected override DbConnection? DbConnection { get; set; }
            protected override DbParameterCollection DbParameterCollection => _params;
            protected override DbTransaction? DbTransaction { get; set; }

            public override void Cancel() { }
            public override int ExecuteNonQuery() => 1;

            // ExecuteScalar returns a predictable blab_name so downstream string-building works.
            public override object? ExecuteScalar() => "TestBlabName";

            public override void Prepare() { }

            protected override DbParameter CreateDbParameter() => new FakeDbParameter();

            protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior)
                => throw new NotImplementedException();

            // After execution capture parameters for assertion.
            protected override void Dispose(bool disposing)
            {
                foreach (FakeDbParameter p in _params)
                    Captured.Parameters.Add((p.ParameterName ?? "", p.Value ?? DBNull.Value));
                base.Dispose(disposing);
            }
        }

        private class FakeDbParameter : DbParameter
        {
            public override DbType DbType { get; set; }
            public override ParameterDirection Direction { get; set; }
            public override bool IsNullable { get; set; }
            public override string? ParameterName { get; set; }
            public override int Size { get; set; }
            public override string? SourceColumn { get; set; }
            public override bool SourceColumnNullMapping { get; set; }
            public override object? Value { get; set; }
            public override void ResetDbType() { }
        }

        private class FakeDbParameterCollection : DbParameterCollection
        {
            private readonly List<FakeDbParameter> _items = new();

            public override int Count => _items.Count;
            public override object SyncRoot => _items;

            public override int Add(object value)
            {
                _items.Add((FakeDbParameter)value);
                return _items.Count - 1;
            }
            public override void AddRange(Array values) =>
                throw new NotImplementedException();
            public override void Clear() => _items.Clear();
            public override bool Contains(string value) => throw new NotImplementedException();
            public override bool Contains(object value) => _items.Contains((FakeDbParameter)value);
            public override void CopyTo(Array array, int index) =>
                throw new NotImplementedException();
            public override System.Collections.IEnumerator GetEnumerator() => _items.GetEnumerator();
            public override int IndexOf(string parameterName) => throw new NotImplementedException();
            public override int IndexOf(object value) => _items.IndexOf((FakeDbParameter)value);
            public override void Insert(int index, object value) =>
                _items.Insert(index, (FakeDbParameter)value);
            public override void Remove(object value) =>
                _items.Remove((FakeDbParameter)value);
            public override void RemoveAt(string parameterName) =>
                throw new NotImplementedException();
            public override void RemoveAt(int index) => _items.RemoveAt(index);
            protected override DbParameter GetParameter(string parameterName) =>
                _items.Find(p => p.ParameterName == parameterName)!;
            protected override DbParameter GetParameter(int index) => _items[index];
            protected override void SetParameter(string parameterName, DbParameter value) =>
                throw new NotImplementedException();
            protected override void SetParameter(int index, DbParameter value) =>
                throw new NotImplementedException();
        }

        /// <summary>
        /// A fake DbConnection that returns FakeDbCommand instances for each
        /// CreateCommand() call and records them for later inspection.
        /// </summary>
        private class FakeDbConnection : DbConnection
        {
            private readonly Queue<FakeDbCommand> _commands;
            public List<FakeDbCommand> IssuedCommands { get; } = new();

            public FakeDbConnection(IEnumerable<FakeDbCommand> commands)
            {
                _commands = new Queue<FakeDbCommand>(commands);
            }

            public override string ConnectionString { get; set; } = string.Empty;
            public override string Database => "FakeDb";
            public override string DataSource => "FakeSource";
            public override string ServerVersion => "1.0";
            public override ConnectionState State => ConnectionState.Open;

            public override void ChangeDatabase(string databaseName) { }
            public override void Close() { }
            public override void Open() { }

            protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel)
                => throw new NotImplementedException();

            protected override DbCommand CreateDbCommand()
            {
                var cmd = _commands.Count > 0 ? _commands.Dequeue() : new FakeDbCommand();
                IssuedCommands.Add(cmd);
                return cmd;
            }
        }

        // -----------------------------------------------------------------------
        // Tests
        // -----------------------------------------------------------------------

        /// <summary>
        /// The SELECT query must use a named parameter placeholder (not raw string
        /// concatenation) so user-supplied blabberUsername cannot alter the query structure.
        /// </summary>
        [Fact]
        public void Execute_SelectQuery_UsesParameterizedQuery()
        {
            // Arrange
            var deleteCmd   = new FakeDbCommand();
            var selectCmd   = new FakeDbCommand();
            var insertCmd   = new FakeDbCommand();
            var connection  = new FakeDbConnection(new[] { deleteCmd, selectCmd, insertCmd });
            var command     = new IgnoreCommand(connection, "currentUser");

            // Act
            command.Execute("normalUser");

            // Assert: the SELECT CommandText must NOT contain the raw username value;
            // it must contain a parameter placeholder instead.
            Assert.DoesNotContain("normalUser", selectCmd.Captured.CommandText,
                StringComparison.Ordinal);
            Assert.Contains("@blabberUsername", selectCmd.Captured.CommandText,
                StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The SELECT parameter must carry the exact blabberUsername value as data,
        /// not encoded into the SQL text.
        /// </summary>
        [Fact]
        public void Execute_SelectQuery_ParameterContainsBlabberUsername()
        {
            // Arrange
            var deleteCmd  = new FakeDbCommand();
            var selectCmd  = new FakeDbCommand();
            var insertCmd  = new FakeDbCommand();
            var connection = new FakeDbConnection(new[] { deleteCmd, selectCmd, insertCmd });
            var command    = new IgnoreCommand(connection, "currentUser");

            // Act
            command.Execute("targetUser");

            // Force parameter capture via Dispose
            selectCmd.Dispose();

            // Assert
            Assert.Contains(selectCmd.Captured.Parameters,
                p => p.Name.Equals("@blabberUsername", StringComparison.OrdinalIgnoreCase)
                  && p.Value?.ToString() == "targetUser");
        }

        /// <summary>
        /// An SQL injection payload in blabberUsername must NOT appear in the
        /// SELECT CommandText — it must only be present as a parameter value.
        /// </summary>
        [Fact]
        public void Execute_SelectQuery_SqlInjectionPayloadIsNotInCommandText()
        {
            // Arrange
            const string injectionPayload = "' OR '1'='1";
            var deleteCmd  = new FakeDbCommand();
            var selectCmd  = new FakeDbCommand();
            var insertCmd  = new FakeDbCommand();
            var connection = new FakeDbConnection(new[] { deleteCmd, selectCmd, insertCmd });
            var command    = new IgnoreCommand(connection, "currentUser");

            // Act
            command.Execute(injectionPayload);

            // Assert: the raw payload must not appear in the SQL string
            Assert.DoesNotContain(injectionPayload, selectCmd.Captured.CommandText,
                StringComparison.Ordinal);
        }

        /// <summary>
        /// An SQL injection payload must not appear raw in the INSERT CommandText either.
        /// The INSERT must also use parameter placeholders.
        /// </summary>
        [Fact]
        public void Execute_InsertQuery_SqlInjectionPayloadIsNotInCommandText()
        {
            // Arrange
            const string injectionPayload = "\"); DROP TABLE users; --";
            var deleteCmd  = new FakeDbCommand();
            var selectCmd  = new FakeDbCommand();
            var insertCmd  = new FakeDbCommand();
            var connection = new FakeDbConnection(new[] { deleteCmd, selectCmd, insertCmd });
            var command    = new IgnoreCommand(connection, "currentUser");

            // Act
            command.Execute(injectionPayload);

            // Assert: the INSERT text must not contain the raw payload
            Assert.DoesNotContain(injectionPayload, insertCmd.Captured.CommandText,
                StringComparison.Ordinal);
            // Must use parameter placeholders
            Assert.Contains("@", insertCmd.Captured.CommandText, StringComparison.Ordinal);
        }

        /// <summary>
        /// The DELETE query (already parameterized before the fix) should continue
        /// to use parameter placeholders.
        /// </summary>
        [Fact]
        public void Execute_DeleteQuery_IsParameterized()
        {
            // Arrange
            var deleteCmd  = new FakeDbCommand();
            var selectCmd  = new FakeDbCommand();
            var insertCmd  = new FakeDbCommand();
            var connection = new FakeDbConnection(new[] { deleteCmd, selectCmd, insertCmd });
            var command    = new IgnoreCommand(connection, "currentUser");

            // Act
            command.Execute("victim");

            // Assert
            Assert.DoesNotContain("victim", deleteCmd.Captured.CommandText,
                StringComparison.Ordinal);
            Assert.Contains("@blabber", deleteCmd.Captured.CommandText,
                StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Verify that Execute completes without throwing for a normal (benign) input.
        /// This ensures the parameterized queries maintain backward-compatible behavior.
        /// </summary>
        [Fact]
        public void Execute_NormalInput_DoesNotThrow()
        {
            // Arrange
            var deleteCmd  = new FakeDbCommand();
            var selectCmd  = new FakeDbCommand();
            var insertCmd  = new FakeDbCommand();
            var connection = new FakeDbConnection(new[] { deleteCmd, selectCmd, insertCmd });
            var command    = new IgnoreCommand(connection, "alice");

            // Act & Assert (no exception thrown)
            var ex = Record.Exception(() => command.Execute("bob"));
            Assert.Null(ex);
        }

        /// <summary>
        /// A payload containing single-quote SQL metacharacters must not be able to
        /// alter query structure — the query text stays constant regardless of input.
        /// </summary>
        [Theory]
        [InlineData("'; DROP TABLE users; --")]
        [InlineData("' UNION SELECT password FROM users --")]
        [InlineData("admin'--")]
        [InlineData("' OR 1=1; --")]
        public void Execute_SelectQuery_VariousInjectionPayloads_DoNotAlterQueryStructure(
            string payload)
        {
            // Arrange
            var deleteCmd  = new FakeDbCommand();
            var selectCmd  = new FakeDbCommand();
            var insertCmd  = new FakeDbCommand();
            var connection = new FakeDbConnection(new[] { deleteCmd, selectCmd, insertCmd });
            var command    = new IgnoreCommand(connection, "currentUser");

            // Capture the query text that a benign call produces
            var deleteRef  = new FakeDbCommand();
            var selectRef  = new FakeDbCommand();
            var insertRef  = new FakeDbCommand();
            var connRef    = new FakeDbConnection(new[] { deleteRef, selectRef, insertRef });
            var cmdRef     = new IgnoreCommand(connRef, "currentUser");
            cmdRef.Execute("benignUser");
            string expectedSelectText = selectRef.Captured.CommandText;

            // Act
            command.Execute(payload);

            // Assert: query structure is identical regardless of payload
            Assert.Equal(expectedSelectText, selectCmd.Captured.CommandText);
        }
    }
}
