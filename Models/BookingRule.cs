//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace TotalSquashNext.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class BookingRule
    {
        public BookingRule()
        {
            this.Bookings = new HashSet<Booking>();
        }
    
        public int bookingRuleId { get; set; }
        public int organizationID { get; set; }
        public int daysInAdvance { get; set; }
        public int numOfBookings { get; set; }
        public int numOfStrikes { get; set; }
    
        public virtual ICollection<Booking> Bookings { get; set; }
    }
}
