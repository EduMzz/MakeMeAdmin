namespace SinclairCC.MakeMeAdmin
{
    using System.Runtime.Serialization;

    /// <summary>
    /// A bounded snapshot of the user who initiated an elevated remote request.
    /// It is produced by the local service after binding the administrator token
    /// to its interactive session, then checked against the destination policy.
    /// </summary>
    [DataContract]
    public sealed class RemoteRequestIdentity
    {
        [DataMember(Order = 1, IsRequired = true)]
        public string Sid { get; set; }

        [DataMember(Order = 2, IsRequired = true)]
        public string Name { get; set; }

        [DataMember(Order = 3, IsRequired = true)]
        public string[] GroupSids { get; set; }
    }
}
