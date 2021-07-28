using System;

namespace TodoApp.Models
{
    public class ItemData
    {
        public Guid Id { get; set; }
        public string Title { get; set; }
        public string Details { get; set; }
        public bool Done { get; set; }
    }
}