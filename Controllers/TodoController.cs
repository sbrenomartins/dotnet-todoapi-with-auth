using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TodoApp.Data;
using TodoApp.Models;

namespace TodoApp.Controllers
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class TodoController : ControllerBase
    {
        private readonly ApiDbContext _context;

        public TodoController(ApiDbContext context)
        {
            _context = context;
        }

        [Route("TestRun")]
        [HttpGet]
        public ActionResult TestRun() 
        {
            return Ok("success");
        }

        [HttpGet]
        public ActionResult GetItems()
        {
            List<ItemData> items = _context.Items.ToList();
            return Ok(items);
        }

        [HttpGet("{Id}")]
        public async Task<IActionResult> GetItem(Guid Id)
        {
            ItemData item = await _context.Items.FirstOrDefaultAsync(i => i.Id == Id);

            if (item == null)
                return NotFound();

            return Ok(item);
        }

        [HttpPost]
        public async Task<IActionResult> CreateItem(ItemData data)
        {
            if(ModelState.IsValid)
            {
                await _context.Items.AddAsync(data);
                await _context.SaveChangesAsync();

                return CreatedAtAction("GetItem", new {data.Id}, data);
            }

            return new JsonResult("Something went wrong!") { StatusCode = 500 };
        }

        [HttpPut("{Id}")]
        public async Task<IActionResult> UpdateItem(Guid Id, ItemData data)
        {
            if(Id != data.Id)
                return BadRequest();

            ItemData existItem = await _context.Items.FirstOrDefaultAsync(i => i.Id == Id);

            if(existItem == null)
                return NotFound();

            existItem.Title = data.Title;
            existItem.Details = data.Details;
            existItem.Done = data.Done;

            await _context.SaveChangesAsync();

            //Following up the REST standard on update we need to return NoContent;
            return NoContent();
        }

        [HttpDelete("{Id}")]
        public async Task<IActionResult> DeleteItem(Guid Id)
        {
            ItemData existItem = await _context.Items.FirstOrDefaultAsync(i => i.Id == Id);

            if(existItem == null) 
                return NotFound();

            _context.Items.Remove(existItem);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}