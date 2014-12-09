// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_HASH_H
#define FILE_ANALYSIS_HASH_H

#include <string>
#include <sstream>
#include "Val.h"
#include "OpaqueVal.h"
#include "File.h"
#include "Analyzer.h"

#include "events.bif.h"

#include <yara.h>

namespace file_analysis {

/**
 * An analyzer to produce a hash of file contents.
 */
class Yara : public file_analysis::Analyzer {
public:

	/**
	 * Destructor.
	 */
	virtual ~Yara();

	/**
	 * Incrementally hash next chunk of file contents.
	 * @param data pointer to start of a chunk of a file data.
	 * @param len number of bytes in the data chunk.
	 * @return false if the digest is in an invalid state, else true.
	 */
	virtual bool DeliverStream(const u_char* data, uint64 len);

	/**
	 * Finalizes the hash and raises a "file_hash" event.
	 * @return always false so analyze will be deteched from file.
	 */
	virtual bool EndOfFile();

	/**
	 * Missing data can't be handled, so just indicate the this analyzer should
	 * be removed from receiving further data.  The hash will not be finalized.
	 * @param offset byte offset in file at which missing chunk starts.
	 * @param len number of missing bytes.
	 * @return always false so analyzer will detach from file.
	 */
	virtual bool Undelivered(uint64 offset, uint64 len);

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ 
			return new Yara(args,file,"yara");
			// return file_yarahash ? new YARA(args, file) : 0; 
		}


	void raiseEvent(int message,void* message_data);


protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param hv specific hash calculator object.
	 * @param kind human readable name of the hash algorithm to use.
	 */
	Yara(RecordVal* args, File* file,  const char* kind);

	/**
	 * If some file contents have been seen, finalizes the hash of them and
	 * raises the "file_hash" event with the results.
	 */
	void Finalize();

private:
	YR_RULES* yr_rules_;
	std::ostringstream ostream_;
	bool fed;
	const char* kind;
};





} // namespace file_analysis

#endif
