import { MongoClient } from 'mongodb'

const uri = process.env.MONGODB_URI

if (!uri) {
  throw new Error('Please add your MongoDB URI to .env.local')
}

let client
let clientPromise

// Reuse the MongoDB client across serverless invocations in both dev and prod.
// Using a global variable prevents new connections from being created on every
// warm serverless call, which significantly reduces CPU time on Vercel.
if (!global._mongoClientPromise) {
  client = new MongoClient(uri, { tls: true })
  global._mongoClientPromise = client.connect()
}
clientPromise = global._mongoClientPromise

export default clientPromise
