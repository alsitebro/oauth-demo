using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AuthorisationServer.Data
{
    public interface IDataContext<T>
    {
        Task CreateOneAsync(T item);
        List<T> ToList();
        Task<T> FindAsync(string id);
        Task<List<T>> FindAsync(Func<T, bool> predicate);
        Task<T> SingleOrDefaultAsync(Func<T, bool> predicate);
        Task UpdateOneAsync(string id, T item);
        Task DeleteOneAsync(string id);
    }
}