//
// Copyright © 2010-2025, Sinclair Community College
// Licensed under the GNU General Public License, version 3.
//
namespace SinclairCC.MakeMeAdmin
{
    using System;
    using System.Drawing;
    using System.Windows.Forms;

    /// <summary>
    /// Administrator console hosted by the privileged service module. It uses
    /// the same command handlers as the SSH/PowerShell interface.
    /// </summary>
    internal sealed class AdminManagementForm : Form
    {
        private readonly TextBox commandBox;
        private readonly TextBox outputBox;

        internal AdminManagementForm()
        {
            Text = "Make Me Admin — Administração";
            Icon = Properties.Resources.SecurityLock;
            MinimumSize = new Size(760, 480);
            StartPosition = FormStartPosition.CenterScreen;

            Label guidance = new Label
            {
                Text = "Comandos: config list | config set <nome> <valor> | sessions list | grants list | grant-session <sessão> [minutos] | revoke <SID> | audit [quantidade]",
                Dock = DockStyle.Fill,
                AutoSize = false,
                Padding = new Padding(8),
                TextAlign = ContentAlignment.MiddleLeft
            };

            outputBox = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Both,
                WordWrap = false,
                Dock = DockStyle.Fill,
                Font = new Font(FontFamily.GenericMonospace, 9.0f)
            };

            commandBox = new TextBox { Dock = DockStyle.Fill };
            commandBox.KeyDown += (sender, eventArgs) =>
            {
                if ((eventArgs.KeyCode == Keys.Enter) && !eventArgs.Shift)
                {
                    eventArgs.SuppressKeyPress = true;
                    RunCommand();
                }
            };

            Button runButton = new Button { Text = "Executar", Dock = DockStyle.Fill, AutoSize = true };
            runButton.Click += (sender, eventArgs) => RunCommand();

            TableLayoutPanel layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 4,
                Padding = new Padding(8)
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 8));
            layout.Controls.Add(guidance, 0, 0);
            layout.SetColumnSpan(guidance, 2);
            layout.Controls.Add(outputBox, 0, 1);
            layout.SetColumnSpan(outputBox, 2);
            layout.Controls.Add(commandBox, 0, 2);
            layout.Controls.Add(runButton, 1, 2);
            Controls.Add(layout);
            AcceptButton = runButton;

            Shown += (sender, eventArgs) =>
            {
                commandBox.Text = "config list";
                RunCommand();
            };
        }

        private void RunCommand()
        {
            try
            {
                string output = Program.ExecuteAdminCommandForGui(commandBox.Text);
                outputBox.Text = output;
                outputBox.SelectionStart = outputBox.TextLength;
                outputBox.ScrollToCaret();
            }
            catch (Exception exception)
            {
                outputBox.Text = exception.Message;
            }
        }
    }
}
