using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorisationServer.Data
{
    public class MongoDataContext<T> : IDataContext<T> where T : BaseEntity
    {
        private readonly IMongoCollection<T> _collection;

        public MongoDataContext(IMongoCollection<T> collection)
        {
            _collection = collection;
        }

        public Task CreateOneAsync(T item)
        {
            return _collection.InsertOneAsync(item);
        }

        public List<T> ToList()
        {
            return _collection.Find(Builders<T>.Filter.Empty).ToList();
        }

        public Task<T> FindAsync(string id)
        {
            var entity = _collection.Find(i => i.Id == id).ToCursor().Current.SingleOrDefault();
            return Task.FromResult(entity);
        }

        public Task<List<T>> FindAsync(Func<T, bool> predicate)
        {
            var entities = _collection.AsQueryable().Where(predicate).ToList();
            return Task.FromResult(entities);
        }

        public Task<T> SingleOrDefaultAsync(Func<T, bool> predicate)
        {
            var entity = _collection.AsQueryable().SingleOrDefault(predicate);
            return Task.FromResult(entity);
        }

        public async Task UpdateOneAsync(string id, T item)
        {
            var doc = await _collection.Find(Builders<T>.Filter.Eq(x => x.Id, id)).SingleOrDefaultAsync();
            if (doc == null)
            {
                _collection.InsertOne(item);
            }
            else
            {
                await _collection.FindOneAndReplaceAsync(Builders<T>.Filter.Eq("_id", id), item).ConfigureAwait(false);
            }
        }

        public Task DeleteOneAsync(string id)
        {
            return _collection.FindOneAndDeleteAsync(i => i.Id == id);
        }
    }
}