namespace SinclairCC.MakeMeAdmin
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Threading.Tasks;
    using System.Windows.Forms;

    /// <summary>
    /// The original remote request workflow, hosted by the standard-user module.
    /// Every request launches the protected helper through Windows UAC first.
    /// </summary>
    internal sealed class RemoteRequestForm : Form
    {
        private readonly ComboBox hostBox;
        private readonly Button requestButton;
        private readonly Button clearButton;
        private readonly Label statusLabel;
        private readonly string historyPath;

        internal RemoteRequestForm()
        {
            Text = "Make Me Admin — Remote request";
            Icon = Properties.Resources.SecurityLock;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new System.Drawing.Size(520, 150);

            string appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Make Me Admin");
            Directory.CreateDirectory(appData);
            historyPath = Path.Combine(appData, "remote-hosts.txt");

            Label hostLabel = new Label { Text = "Computer name", AutoSize = true, Anchor = AnchorStyles.Left };
            hostBox = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDown, AutoCompleteMode = AutoCompleteMode.SuggestAppend, AutoCompleteSource = AutoCompleteSource.ListItems };
            requestButton = new Button { Text = "Request rights", AutoSize = true };
            clearButton = new Button { Text = "Clear history", AutoSize = true };
            statusLabel = new Label { Text = "Windows will ask an administrator to authorize each request.", AutoSize = true, Dock = DockStyle.Fill };

            TableLayoutPanel layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(10), ColumnCount = 3, RowCount = 3 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.Controls.Add(hostLabel, 0, 0);
            layout.Controls.Add(hostBox, 1, 0);
            layout.SetColumnSpan(hostBox, 2);
            layout.Controls.Add(requestButton, 1, 1);
            layout.Controls.Add(clearButton, 2, 1);
            layout.Controls.Add(statusLabel, 0, 2);
            layout.SetColumnSpan(statusLabel, 3);
            Controls.Add(layout);

            requestButton.Click += async (sender, eventArgs) => await RequestRightsAsync();
            clearButton.Click += (sender, eventArgs) => ClearHistory();
            hostBox.KeyDown += async (sender, eventArgs) =>
            {
                if (eventArgs.KeyCode == Keys.Enter)
                {
                    eventArgs.SuppressKeyPress = true;
                    await RequestRightsAsync();
                }
            };
            LoadHistory();
        }

        private async Task RequestRightsAsync()
        {
            string host = hostBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(host) || (host.Length > 253) || (Uri.CheckHostName(host) == UriHostNameType.Unknown)
                || host.Any(char.IsWhiteSpace) || host.IndexOfAny(new[] { '/', '\\', '"' }) >= 0)
            {
                MessageBox.Show(this, "Enter a valid computer name or IP address.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            AddToHistory(host);
            hostBox.Enabled = requestButton.Enabled = clearButton.Enabled = false;
            statusLabel.Text = "Waiting for administrator authorization…";
            try
            {
                string serviceExecutable = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MakeMeAdminService.exe");
                if (!File.Exists(serviceExecutable)) { throw new FileNotFoundException("The protected administrator module was not found.", serviceExecutable); }
                int exitCode = await Task.Run(() =>
                {
                    ProcessStartInfo startInfo = new ProcessStartInfo(serviceExecutable, "--grant-remote \"" + host + "\"")
                    {
                        UseShellExecute = true,
                        Verb = "runas",
                        WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
                    };
                    using (Process process = Process.Start(startInfo))
                    {
                        if (process == null) { throw new InvalidOperationException("Windows did not start the administrator approval helper."); }
                        process.WaitForExit();
                        return process.ExitCode;
                    }
                });

                if (exitCode == 0) { statusLabel.Text = "The destination accepted the administrator-approved request."; }
                else if (exitCode == 1223) { statusLabel.Text = "The request was canceled."; }
                else { statusLabel.Text = "The request was denied or the destination could not grant access (code " + exitCode + ")."; }
            }
            catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1223)
            {
                statusLabel.Text = "The administrator canceled the UAC prompt.";
            }
            catch (Exception exception)
            {
                statusLabel.Text = "The request failed.";
                MessageBox.Show(this, exception.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                hostBox.Enabled = requestButton.Enabled = clearButton.Enabled = true;
            }
        }

        private void LoadHistory()
        {
            try
            {
                if (!File.Exists(historyPath)) { return; }
                foreach (string host in File.ReadAllLines(historyPath).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).Take(10))
                {
                    hostBox.Items.Add(host);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private void AddToHistory(string host)
        {
            string[] hosts = new[] { host }.Concat(hostBox.Items.Cast<object>().Select(item => Convert.ToString(item)))
                .Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).Take(10).ToArray();
            hostBox.Items.Clear();
            hostBox.Items.AddRange(hosts);
            hostBox.Text = host;
            try { File.WriteAllLines(historyPath, hosts); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private void ClearHistory()
        {
            hostBox.Items.Clear();
            try { if (File.Exists(historyPath)) { File.Delete(historyPath); } }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
