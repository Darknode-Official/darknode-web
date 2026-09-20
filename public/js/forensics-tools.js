// Darknode Forensics Tools -- a self-contained suite of digital forensics
// reference material and analysis utilities. Everything runs client-side in
// the browser: no network calls, no backend, no frameworks. Pure vanilla JS.
//
// Exported entry point: renderForensicsTools(main)
//
// Tabs:
//   1. File Signatures  -- magic byte lookup / identifier
//   2. Hex Viewer       -- hex dump formatter and inspector
//   3. Timestamp Conv.  -- multi-format forensic timestamp converter
//   4. Win Event IDs    -- searchable Windows event ID reference
//   5. Browser Artifacts -- file path reference for browser forensics

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function pad(n, w) { return String(n).padStart(w, "0"); }

// ---------------------------------------------------------------------------
// SECTION 1: FILE SIGNATURES DATABASE
// ---------------------------------------------------------------------------

const FILE_SIGS = [
  // -- Images --
  { bytes: "89504E47", ext: "png", mime: "image/png", desc: "PNG Image" },
  { bytes: "FFD8FFE0", ext: "jpg", mime: "image/jpeg", desc: "JPEG/JFIF Image" },
  { bytes: "FFD8FFE1", ext: "jpg", mime: "image/jpeg", desc: "JPEG/EXIF Image" },
  { bytes: "FFD8FFEE", ext: "jpg", mime: "image/jpeg", desc: "JPEG (Adobe segment)" },
  { bytes: "FFD8FFDB", ext: "jpg", mime: "image/jpeg", desc: "JPEG (raw quantization table)" },
  { bytes: "FFD8FF", ext: "jpg", mime: "image/jpeg", desc: "JPEG (generic)" },
  { bytes: "474946383761", ext: "gif", mime: "image/gif", desc: "GIF87a Image" },
  { bytes: "474946383961", ext: "gif", mime: "image/gif", desc: "GIF89a Image" },
  { bytes: "424D", ext: "bmp", mime: "image/bmp", desc: "BMP Bitmap Image" },
  { bytes: "49492A00", ext: "tif", mime: "image/tiff", desc: "TIFF Image (Little-Endian)" },
  { bytes: "4D4D002A", ext: "tif", mime: "image/tiff", desc: "TIFF Image (Big-Endian)" },
  { bytes: "00000100", ext: "ico", mime: "image/x-icon", desc: "ICO Icon" },
  { bytes: "00000200", ext: "cur", mime: "image/x-icon", desc: "CUR Cursor" },
  { bytes: "52494646", ext: "webp", mime: "image/webp", desc: "WEBP Image (RIFF container -- check for WEBP at offset 8)" },
  { bytes: "38425053", ext: "psd", mime: "image/vnd.adobe.photoshop", desc: "Adobe Photoshop PSD" },
  { bytes: "3C73766720", ext: "svg", mime: "image/svg+xml", desc: "SVG Image (starts with <svg)" },
  { bytes: "233F52414449414E43", ext: "hdr", mime: "image/vnd.radiance", desc: "Radiance HDR Image" },
  { bytes: "44445320", ext: "dds", mime: "image/vnd.ms-dds", desc: "DirectDraw Surface" },
  { bytes: "0A050108", ext: "pcx", mime: "image/x-pcx", desc: "PCX Image (version 5, 8-bit)" },
  { bytes: "0A030108", ext: "pcx", mime: "image/x-pcx", desc: "PCX Image (version 3, 8-bit)" },
  { bytes: "5031", ext: "pbm", mime: "image/x-portable-bitmap", desc: "PBM Portable Bitmap (ASCII)" },
  { bytes: "5032", ext: "pgm", mime: "image/x-portable-graymap", desc: "PGM Portable Graymap (ASCII)" },
  { bytes: "5033", ext: "ppm", mime: "image/x-portable-pixmap", desc: "PPM Portable Pixmap (ASCII)" },
  { bytes: "5034", ext: "pbm", mime: "image/x-portable-bitmap", desc: "PBM Portable Bitmap (binary)" },
  { bytes: "5035", ext: "pgm", mime: "image/x-portable-graymap", desc: "PGM Portable Graymap (binary)" },
  { bytes: "5036", ext: "ppm", mime: "image/x-portable-pixmap", desc: "PPM Portable Pixmap (binary)" },
  { bytes: "0000000C6A502020", ext: "jp2", mime: "image/jp2", desc: "JPEG 2000 Image" },
  { bytes: "6674797068656963", ext: "heic", mime: "image/heic", desc: "HEIF/HEIC Image (ftyp heic)" },
  { bytes: "6674797061766966", ext: "avif", mime: "image/avif", desc: "AVIF Image (ftyp avif)" },
  { bytes: "676F6F676C65", ext: "webp2", mime: "image/webp", desc: "WEBP2 experimental format" },
  { bytes: "4949BC", ext: "jxr", mime: "image/vnd.ms-photo", desc: "JPEG XR / HD Photo" },

  // -- Documents --
  { bytes: "25504446", ext: "pdf", mime: "application/pdf", desc: "PDF Document" },
  { bytes: "504B0304", ext: "zip", mime: "application/zip", desc: "ZIP Archive (also DOCX/XLSX/PPTX/ODT/EPUB/JAR/APK -- inspect contents)" },
  { bytes: "D0CF11E0A1B1A1E1", ext: "doc", mime: "application/msword", desc: "OLE2 Compound Document (DOC/XLS/PPT/MSI)" },
  { bytes: "7B5C727466", ext: "rtf", mime: "application/rtf", desc: "Rich Text Format" },
  { bytes: "25215053", ext: "ps", mime: "application/postscript", desc: "PostScript Document" },
  { bytes: "41542654464F524D", ext: "djvu", mime: "image/vnd.djvu", desc: "DjVu Document" },
  { bytes: "7B5C", ext: "rtf", mime: "application/rtf", desc: "RTF Document (short signature)" },
  { bytes: "0D444F43", ext: "doc", mime: "application/msword", desc: "Microsoft Word (very old DOS format)" },
  { bytes: "CFAD12FEC5FD746F", ext: "doc", mime: "application/msword", desc: "Microsoft Perfect Office compound" },
  { bytes: "DBA52D00", ext: "doc", mime: "application/msword", desc: "Word 2.0 Document" },

  // -- Archives --
  { bytes: "504B0506", ext: "zip", mime: "application/zip", desc: "ZIP Archive (empty / end of central directory)" },
  { bytes: "504B0708", ext: "zip", mime: "application/zip", desc: "ZIP Archive (spanned)" },
  { bytes: "526172211A0700", ext: "rar", mime: "application/x-rar-compressed", desc: "RAR Archive v4" },
  { bytes: "526172211A070100", ext: "rar", mime: "application/x-rar-compressed", desc: "RAR Archive v5" },
  { bytes: "377ABCAF271C", ext: "7z", mime: "application/x-7z-compressed", desc: "7-Zip Archive" },
  { bytes: "1F8B", ext: "gz", mime: "application/gzip", desc: "GZIP / TAR.GZ Compressed" },
  { bytes: "425A68", ext: "bz2", mime: "application/x-bzip2", desc: "BZip2 Compressed" },
  { bytes: "FD377A585A00", ext: "xz", mime: "application/x-xz", desc: "XZ Compressed" },
  { bytes: "28B52FFD", ext: "zst", mime: "application/zstd", desc: "Zstandard Compressed" },
  { bytes: "04224D18", ext: "lz4", mime: "application/x-lz4", desc: "LZ4 Compressed (frame format)" },
  { bytes: "2D6C68", ext: "lzh", mime: "application/x-lzh-compressed", desc: "LZH/LHA Compressed Archive" },
  { bytes: "5D000080", ext: "lzma", mime: "application/x-lzma", desc: "LZMA Compressed" },
  { bytes: "4D534346", ext: "cab", mime: "application/vnd.ms-cab-compressed", desc: "Microsoft Cabinet Archive" },
  { bytes: "60EA", ext: "arj", mime: "application/x-arj", desc: "ARJ Archive" },
  { bytes: "2A2A414345", ext: "ace", mime: "application/x-ace-compressed", desc: "ACE Archive" },
  { bytes: "5A4F4F20", ext: "zoo", mime: "application/x-zoo", desc: "ZOO Archive" },
  { bytes: "1A", ext: "arc", mime: "application/x-arc", desc: "ARC Archive" },
  { bytes: "C771", ext: "cpio", mime: "application/x-cpio", desc: "CPIO Archive (little-endian binary)" },
  { bytes: "71C7", ext: "cpio", mime: "application/x-cpio", desc: "CPIO Archive (big-endian binary / swapped)" },
  { bytes: "30373037", ext: "cpio", mime: "application/x-cpio", desc: "CPIO Archive (ASCII / newc format '0707')" },
  { bytes: "7573746172", ext: "tar", mime: "application/x-tar", desc: "TAR Archive (ustar magic at offset 257)" },

  // -- Executables --
  { bytes: "4D5A", ext: "exe", mime: "application/x-dosexec", desc: "PE Executable (EXE/DLL/SYS/OCX)" },
  { bytes: "7F454C46", ext: "elf", mime: "application/x-executable", desc: "ELF Executable (Linux/Unix/BSD)" },
  { bytes: "FEEDFACE", ext: "macho", mime: "application/x-mach-binary", desc: "Mach-O 32-bit Binary" },
  { bytes: "FEEDFACF", ext: "macho", mime: "application/x-mach-binary", desc: "Mach-O 64-bit Binary" },
  { bytes: "CEFAEDFE", ext: "macho", mime: "application/x-mach-binary", desc: "Mach-O 32-bit Binary (reverse byte order)" },
  { bytes: "CFFAEDFE", ext: "macho", mime: "application/x-mach-binary", desc: "Mach-O 64-bit Binary (reverse byte order)" },
  { bytes: "CAFEBABE", ext: "class", mime: "application/java", desc: "Mach-O Fat/Universal Binary or Java Class File" },
  { bytes: "6465780A30333500", ext: "dex", mime: "application/x-dex", desc: "Android DEX (Dalvik Executable) v035" },
  { bytes: "6465780A30333900", ext: "dex", mime: "application/x-dex", desc: "Android DEX (Dalvik Executable) v039" },
  { bytes: "6465780A", ext: "dex", mime: "application/x-dex", desc: "Android DEX (Dalvik Executable, generic)" },
  { bytes: "6465790A", ext: "dey", mime: "application/x-dey", desc: "Android ODEX (Optimized DEX)" },
  { bytes: "0061736D", ext: "wasm", mime: "application/wasm", desc: "WebAssembly Binary" },
  { bytes: "0107", ext: "a.out", mime: "application/x-executable", desc: "a.out Executable (PDP-11)" },
  { bytes: "0108", ext: "a.out", mime: "application/x-executable", desc: "a.out Executable (VAX)" },
  { bytes: "010B", ext: "a.out", mime: "application/x-executable", desc: "a.out Executable (68k)" },
  { bytes: "CEFAEDFE", ext: "macho", mime: "application/x-mach-binary", desc: "Mach-O Reversed 32-bit" },
  { bytes: "4550", ext: "pe", mime: "application/x-dosexec", desc: "PE Header (found after MZ DOS stub)" },

  // -- Media: Audio --
  { bytes: "494433", ext: "mp3", mime: "audio/mpeg", desc: "MP3 Audio (ID3v2 tag header)" },
  { bytes: "FFFB", ext: "mp3", mime: "audio/mpeg", desc: "MP3 Audio Frame (MPEG1 Layer 3)" },
  { bytes: "FFF3", ext: "mp3", mime: "audio/mpeg", desc: "MP3 Audio Frame (MPEG2 Layer 3)" },
  { bytes: "FFE3", ext: "mp3", mime: "audio/mpeg", desc: "MP3 Audio Frame (MPEG2.5 Layer 3)" },
  { bytes: "FFF1", ext: "aac", mime: "audio/aac", desc: "AAC Audio (ADTS frame)" },
  { bytes: "FFF9", ext: "aac", mime: "audio/aac", desc: "AAC Audio (ADTS frame, CRC)" },
  { bytes: "664C6143", ext: "flac", mime: "audio/flac", desc: "FLAC Audio" },
  { bytes: "4F676753", ext: "ogg", mime: "audio/ogg", desc: "OGG Container (Vorbis/Opus/Theora)" },
  { bytes: "4D546864", ext: "mid", mime: "audio/midi", desc: "MIDI Audio" },
  { bytes: "2E736E64", ext: "au", mime: "audio/basic", desc: "Sun/NeXT AU Audio" },
  { bytes: "2321414D52", ext: "amr", mime: "audio/amr", desc: "AMR Audio" },
  { bytes: "4D414320", ext: "ape", mime: "audio/x-ape", desc: "Monkey's Audio (APE)" },
  { bytes: "7776706B", ext: "wv", mime: "audio/x-wavpack", desc: "WavPack Audio" },
  { bytes: "2E524D46", ext: "rm", mime: "application/vnd.rn-realmedia", desc: "RealMedia Audio/Video" },
  { bytes: "2E7261FD", ext: "ra", mime: "audio/x-realaudio", desc: "RealAudio" },
  { bytes: "664C6143", ext: "flac", mime: "audio/flac", desc: "FLAC Lossless Audio" },

  // -- Media: Video --
  { bytes: "667479706D703431", ext: "mp4", mime: "video/mp4", desc: "MP4 Video (ftyp mp41)" },
  { bytes: "667479706D703432", ext: "mp4", mime: "video/mp4", desc: "MP4 Video (ftyp mp42)" },
  { bytes: "6674797069736F6D", ext: "mp4", mime: "video/mp4", desc: "MP4 Video (ftyp isom)" },
  { bytes: "667479704D534E56", ext: "mp4", mime: "video/mp4", desc: "MP4 Video (ftyp MSNV -- Sony PSP)" },
  { bytes: "66747970", ext: "mp4", mime: "video/mp4", desc: "MP4/M4A/MOV (generic ftyp box)" },
  { bytes: "6D6F6F76", ext: "mov", mime: "video/quicktime", desc: "QuickTime MOV (moov atom)" },
  { bytes: "6D646174", ext: "mov", mime: "video/quicktime", desc: "QuickTime MOV (mdat atom)" },
  { bytes: "667479707174", ext: "mov", mime: "video/quicktime", desc: "QuickTime MOV (ftyp qt)" },
  { bytes: "464C5601", ext: "flv", mime: "video/x-flv", desc: "Flash Video FLV" },
  { bytes: "1A45DFA3", ext: "mkv", mime: "video/x-matroska", desc: "Matroska/MKV/WEBM Video (EBML header)" },
  { bytes: "3026B2758E66CF11", ext: "wmv", mime: "video/x-ms-wmv", desc: "WMA/WMV/ASF (Windows Media)" },

  // -- Media: Container / RIFF-based --
  { bytes: "52494646", ext: "avi", mime: "video/x-msvideo", desc: "RIFF Container (AVI/WAV/WEBP -- check subtype at offset 8)" },

  // -- Database --
  { bytes: "53514C69746520666F726D6174203300", ext: "sqlite", mime: "application/x-sqlite3", desc: "SQLite Database v3" },
  { bytes: "FE01", ext: "myi", mime: "application/x-mysql", desc: "MySQL MyISAM Index" },
  { bytes: "000100005374616E64617264204A", ext: "mdb", mime: "application/x-msaccess", desc: "Microsoft Access MDB (Standard Jet)" },
  { bytes: "000100005374616E64617264204143", ext: "accdb", mime: "application/msaccess", desc: "Microsoft Access ACCDB" },
  { bytes: "00061561", ext: "db", mime: "application/x-berkeley-db", desc: "Berkeley DB" },
  { bytes: "0061736D01000000", ext: "wasm", mime: "application/wasm", desc: "WebAssembly Module v1" },

  // -- Disk images / Forensic formats --
  { bytes: "D4C3B2A1", ext: "pcap", mime: "application/vnd.tcpdump.pcap", desc: "PCAP Packet Capture (little-endian)" },
  { bytes: "A1B2C3D4", ext: "pcap", mime: "application/vnd.tcpdump.pcap", desc: "PCAP Packet Capture (big-endian)" },
  { bytes: "0A0D0D0A", ext: "pcapng", mime: "application/x-pcapng", desc: "PCAPNG Next-Generation Packet Capture" },
  { bytes: "455646", ext: "e01", mime: "application/x-ewf", desc: "EnCase Evidence File (EVF/E01)" },
  { bytes: "4C454602", ext: "ex01", mime: "application/x-ewf2", desc: "EnCase Evidence File v2 (EWF2/Ex01)" },
  { bytes: "4C000000011402", ext: "lnk", mime: "application/x-ms-shortcut", desc: "Windows Shortcut/Link File" },
  { bytes: "2142444E", ext: "pst", mime: "application/vnd.ms-outlook", desc: "Outlook PST File" },
  { bytes: "4B444D56", ext: "vmdk", mime: "application/x-vmdk", desc: "VMware VMDK Disk Image" },
  { bytes: "636F6E6563746978", ext: "vhd", mime: "application/x-vhd", desc: "Virtual Hard Disk (VHD)" },
  { bytes: "76686478", ext: "vhdx", mime: "application/x-vhdx", desc: "Virtual Hard Disk Extended (VHDX)" },
  { bytes: "3C3C3C20", ext: "vdi", mime: "application/x-virtualbox-vdi", desc: "VirtualBox VDI Disk Image" },
  { bytes: "514649FB", ext: "qcow2", mime: "application/x-qemu-disk", desc: "QEMU QCOW2 Disk Image" },
  { bytes: "514649", ext: "qcow", mime: "application/x-qemu-disk", desc: "QEMU QCOW Disk Image (v1)" },
  { bytes: "7265676600000001", ext: "reg", mime: "application/x-windows-registry", desc: "Windows Registry Hive (regf)" },
  { bytes: "72656766", ext: "reg", mime: "application/x-windows-registry", desc: "Windows Registry Hive (regf, short match)" },
  { bytes: "ACED0005", ext: "ser", mime: "application/x-java-serialized-object", desc: "Java Serialized Object" },

  // -- Package formats --
  { bytes: "213C617263683E", ext: "deb", mime: "application/x-deb", desc: "Debian DEB Package (ar archive)" },
  { bytes: "EDABEEDB", ext: "rpm", mime: "application/x-rpm", desc: "RPM Package" },
  { bytes: "43723234", ext: "crx", mime: "application/x-chrome-extension", desc: "Chrome Extension CRX" },
  { bytes: "7801", ext: "zlib", mime: "application/x-deflate", desc: "ZLIB Compressed (low compression)" },
  { bytes: "785E", ext: "zlib", mime: "application/x-deflate", desc: "ZLIB Compressed (default)" },
  { bytes: "789C", ext: "zlib", mime: "application/x-deflate", desc: "ZLIB Compressed (best compression)" },
  { bytes: "78DA", ext: "zlib", mime: "application/x-deflate", desc: "ZLIB Compressed (maximum / best)" },

  // -- Font files --
  { bytes: "0001000000", ext: "ttf", mime: "font/ttf", desc: "TrueType Font" },
  { bytes: "4F54544F", ext: "otf", mime: "font/otf", desc: "OpenType Font" },
  { bytes: "774F4646", ext: "woff", mime: "font/woff", desc: "Web Open Font Format (WOFF)" },
  { bytes: "774F463200", ext: "woff2", mime: "font/woff2", desc: "Web Open Font Format 2 (WOFF2)" },
  { bytes: "00010000", ext: "ttf", mime: "font/ttf", desc: "TrueType Font (4-byte signature)" },

  // -- Crypto / Certificates --
  { bytes: "2D2D2D2D2D424547494E", ext: "pem", mime: "application/x-pem-file", desc: "PEM Encoded Certificate/Key (-----BEGIN)" },
  { bytes: "308230", ext: "der", mime: "application/x-x509-ca-cert", desc: "DER Encoded Certificate (ASN.1 SEQUENCE)" },
  { bytes: "3082", ext: "der", mime: "application/x-x509-ca-cert", desc: "DER/PFX/P12 Certificate (ASN.1 SEQUENCE short)" },
  { bytes: "7373682D", ext: "pub", mime: "text/plain", desc: "SSH Public Key (ssh-rsa, ssh-ed25519, etc.)" },
  { bytes: "5353482D", ext: "key", mime: "application/x-ssh-key", desc: "OpenSSH Private Key (SSH- header)" },

  // -- Compiled / Bytecode --
  { bytes: "420D0D0A", ext: "pyc", mime: "application/x-python-bytecode", desc: "Python Bytecode (Python 3.8)" },
  { bytes: "550D0D0A", ext: "pyc", mime: "application/x-python-bytecode", desc: "Python Bytecode (Python 3.9)" },
  { bytes: "6F0D0D0A", ext: "pyc", mime: "application/x-python-bytecode", desc: "Python Bytecode (Python 3.10)" },
  { bytes: "A70D0D0A", ext: "pyc", mime: "application/x-python-bytecode", desc: "Python Bytecode (Python 3.11)" },
  { bytes: "CB0D0D0A", ext: "pyc", mime: "application/x-python-bytecode", desc: "Python Bytecode (Python 3.12)" },
  { bytes: "4C01", ext: "obj", mime: "application/x-object", desc: "COFF Object File (i386)" },
  { bytes: "6486", ext: "obj", mime: "application/x-object", desc: "COFF Object File (x86-64)" },

  // -- Web / Markup / Data --
  { bytes: "3C3F786D6C", ext: "xml", mime: "application/xml", desc: "XML Document (<?xml)" },
  { bytes: "3C21444F43", ext: "html", mime: "text/html", desc: "HTML Document (<!DOC...)" },
  { bytes: "3C68746D6C", ext: "html", mime: "text/html", desc: "HTML Document (<html)" },
  { bytes: "3C21646F63", ext: "html", mime: "text/html", desc: "HTML Document (<!doc... lowercase)" },
  { bytes: "EFBBBF", ext: "txt", mime: "text/plain", desc: "UTF-8 BOM (Byte Order Mark)" },
  { bytes: "FFFE", ext: "txt", mime: "text/plain", desc: "UTF-16 LE BOM" },
  { bytes: "FEFF", ext: "txt", mime: "text/plain", desc: "UTF-16 BE BOM" },

  // -- Flash --
  { bytes: "465753", ext: "swf", mime: "application/x-shockwave-flash", desc: "SWF Flash (uncompressed)" },
  { bytes: "435753", ext: "swf", mime: "application/x-shockwave-flash", desc: "SWF Flash (ZLIB compressed)" },
  { bytes: "5A5753", ext: "swf", mime: "application/x-shockwave-flash", desc: "SWF Flash (LZMA compressed)" },

  // -- Scientific / Big Data --
  { bytes: "50415231", ext: "parquet", mime: "application/x-parquet", desc: "Apache Parquet Columnar Data" },
  { bytes: "4152524F5731", ext: "arrow", mime: "application/x-arrow", desc: "Apache Arrow IPC Format" },
  { bytes: "894844460D0A1A0A", ext: "hdf5", mime: "application/x-hdf5", desc: "HDF5 (Hierarchical Data Format)" },
  { bytes: "53494D504C4520", ext: "fits", mime: "application/fits", desc: "FITS (Flexible Image Transport System)" },
  { bytes: "43444601", ext: "nc", mime: "application/x-netcdf", desc: "NetCDF (classic format)" },
  { bytes: "89484446", ext: "nc", mime: "application/x-netcdf", desc: "NetCDF-4 / HDF5-based" },

  // -- Misc --
  { bytes: "64383A", ext: "torrent", mime: "application/x-bittorrent", desc: "BitTorrent Metafile" },
  { bytes: "4D4544", ext: "mdf", mime: "application/x-media-descriptor", desc: "Alcohol 120% MDF Disk Image" },
  { bytes: "00FF", ext: "sys", mime: "application/octet-stream", desc: "DOS System Driver" },
  { bytes: "21", ext: "ics", mime: "text/calendar", desc: "iCalendar File (may match many)" },
  { bytes: "BEGIN3A", ext: "vcf", mime: "text/vcard", desc: "vCard Contact File" },
  { bytes: "504B030414", ext: "xlsx", mime: "application/vnd.openxmlformats", desc: "Office Open XML (XLSX/DOCX/PPTX with specific local header)" },
  { bytes: "4F676753", ext: "ogv", mime: "video/ogg", desc: "OGG Video (Theora)" },
  { bytes: "464F524D", ext: "aiff", mime: "audio/aiff", desc: "AIFF Audio / IFF container (FORM)" },
  { bytes: "4D5A9000", ext: "exe", mime: "application/x-dosexec", desc: "PE Executable (common DOS stub variant)" },
  { bytes: "7F454C4602", ext: "elf", mime: "application/x-executable", desc: "ELF 64-bit Executable" },
  { bytes: "7F454C4601", ext: "elf", mime: "application/x-executable", desc: "ELF 32-bit Executable" },
  { bytes: "1F9D", ext: "z", mime: "application/x-compress", desc: "Unix Compress (.Z)" },
  { bytes: "1FA0", ext: "z", mime: "application/x-compress", desc: "Unix Compress (.Z, LZH method)" },
  { bytes: "4344303031", ext: "iso", mime: "application/x-iso9660-image", desc: "ISO 9660 CD/DVD Image (at offset 0x8001)" },
  { bytes: "4E45531A", ext: "nes", mime: "application/x-nes-rom", desc: "Nintendo NES ROM (iNES header)" },
  { bytes: "AB4B5458", ext: "ktx", mime: "image/ktx", desc: "Khronos KTX Texture" },
  { bytes: "7573746172003030", ext: "tar", mime: "application/x-tar", desc: "TAR Archive (POSIX ustar)" },
  { bytes: "7B0A", ext: "json", mime: "application/json", desc: "JSON Data (object, formatted)" },
  { bytes: "5B0A", ext: "json", mime: "application/json", desc: "JSON Data (array, formatted)" },
  { bytes: "7B22", ext: "json", mime: "application/json", desc: "JSON Data (object, compact)" },
  { bytes: "474E5550", ext: "gpg", mime: "application/pgp-encrypted", desc: "GnuPG/GPG Encrypted Data" },
  { bytes: "8950", ext: "gpg", mime: "application/pgp-encrypted", desc: "GPG public key packet (old format)" },
  { bytes: "C50D0D0A", ext: "pyc", mime: "application/x-python-bytecode", desc: "Python Bytecode (Python 3.13)" },
  { bytes: "F9BEB4D9", ext: "dat", mime: "application/x-bitcoin", desc: "Bitcoin Block (mainnet magic)" },
  { bytes: "FABFB5DA", ext: "dat", mime: "application/x-bitcoin", desc: "Bitcoin Block (testnet magic)" },
  { bytes: "D9B4BEF9", ext: "dat", mime: "application/x-ethereum", desc: "Ethereum RLP Data (common pattern)" },
  { bytes: "000000", ext: "mp4", mime: "video/mp4", desc: "MP4/MOV Box (size header -- check ftyp/moov at offset 4)" },
  { bytes: "52617221", ext: "rar", mime: "application/x-rar-compressed", desc: "RAR Archive (short Rar! match)" },
  { bytes: "4D53434600000000", ext: "cab", mime: "application/vnd.ms-cab-compressed", desc: "Microsoft Cabinet (full header)" },
  { bytes: "464F524D00", ext: "aiff", mime: "audio/aiff", desc: "AIFF/IFF Audio (FORM with size byte)" },
  { bytes: "52494646", ext: "wav", mime: "audio/wav", desc: "RIFF/WAV Audio (check WAVE at offset 8)" },
  { bytes: "0000001C66747970", ext: "mp4", mime: "video/mp4", desc: "MP4/M4V (28-byte box + ftyp)" },
  { bytes: "0000002066747970", ext: "mp4", mime: "video/mp4", desc: "MP4 (32-byte box + ftyp)" },
  { bytes: "4C5646090D0A1A0A", ext: "lvf", mime: "application/x-lvf", desc: "LVF Video Format" },
  { bytes: "3C4D616B6566696C65", ext: "mak", mime: "text/x-makefile", desc: "Makefile (text, starts with <Makefile)" },
  { bytes: "23210A", ext: "sh", mime: "text/x-shellscript", desc: "Shell Script (shebang #!\\n)" },
  { bytes: "2321", ext: "sh", mime: "text/x-shellscript", desc: "Script with shebang (#!)" },
];

// ---------------------------------------------------------------------------
// SECTION 2: WINDOWS EVENT IDS DATABASE
// ---------------------------------------------------------------------------

const WIN_EVENTS = [
  // -- Security: Logon/Logoff --
  { id: 4624, channel: "Security", desc: "Successful logon", significance: "Track who logged in, when, and how (logon type field is key)", severity: "info" },
  { id: 4625, channel: "Security", desc: "Failed logon attempt", significance: "Brute-force detection, credential guessing, lateral movement attempts", severity: "medium" },
  { id: 4634, channel: "Security", desc: "Account logoff", significance: "Session duration analysis, correlate with logon events", severity: "info" },
  { id: 4647, channel: "Security", desc: "User-initiated logoff", significance: "Distinguishes intentional logout from session timeout", severity: "info" },
  { id: 4648, channel: "Security", desc: "Logon using explicit credentials", significance: "Credential theft detection, runas usage, lateral movement via explicit creds", severity: "medium" },
  { id: 4649, channel: "Security", desc: "Replay attack detected", significance: "Kerberos replay attack indicator -- critical security event", severity: "critical" },
  { id: 4672, channel: "Security", desc: "Special privileges assigned to logon", significance: "Admin/elevated logon, track privileged sessions", severity: "medium" },
  { id: 4778, channel: "Security", desc: "Session reconnected to window station", significance: "RDP session reconnect, track remote sessions", severity: "info" },
  { id: 4779, channel: "Security", desc: "Session disconnected from window station", significance: "RDP session disconnect, may indicate session hijacking", severity: "info" },

  // -- Security: Process tracking --
  { id: 4688, channel: "Security", desc: "New process created", significance: "Process execution tracking, command-line auditing, malware execution chain", severity: "info" },
  { id: 4689, channel: "Security", desc: "Process exited", significance: "Process lifecycle tracking, correlate with creation events", severity: "low" },
  { id: 4697, channel: "Security", desc: "Service installed in the system", significance: "Persistence mechanism, malware service installation", severity: "high" },

  // -- Security: Scheduled tasks --
  { id: 4698, channel: "Security", desc: "Scheduled task created", significance: "Persistence mechanism, lateral movement, backdoor scheduling", severity: "high" },
  { id: 4699, channel: "Security", desc: "Scheduled task deleted", significance: "Anti-forensics, cleanup after attack", severity: "medium" },
  { id: 4700, channel: "Security", desc: "Scheduled task enabled", significance: "Previously disabled task reactivated", severity: "medium" },
  { id: 4701, channel: "Security", desc: "Scheduled task disabled", significance: "Defensive or evasive action on task", severity: "info" },
  { id: 4702, channel: "Security", desc: "Scheduled task updated", significance: "Task modification may indicate tampering", severity: "medium" },

  // -- Security: Token/Privilege --
  { id: 4703, channel: "Security", desc: "Token right adjusted", significance: "Privilege escalation, token manipulation", severity: "medium" },
  { id: 4704, channel: "Security", desc: "User right assigned", significance: "Privilege assignment, policy change indicator", severity: "medium" },

  // -- Security: Trust --
  { id: 4706, channel: "Security", desc: "New trust created to a domain", significance: "Domain trust creation, potential forest compromise", severity: "high" },
  { id: 4707, channel: "Security", desc: "Trust to a domain removed", significance: "Domain trust removal, may indicate cleanup or attack", severity: "high" },

  // -- Security: Kerberos --
  { id: 4713, channel: "Security", desc: "Kerberos policy changed", significance: "Kerberos ticket policies altered, Golden Ticket indicator", severity: "high" },
  { id: 4716, channel: "Security", desc: "Trusted domain information modified", significance: "Trust relationship modified, cross-domain attack indicator", severity: "high" },
  { id: 4768, channel: "Security", desc: "Kerberos TGT requested (AS-REQ)", significance: "Authentication event, Kerberoasting / AS-REP roasting indicator", severity: "info" },
  { id: 4769, channel: "Security", desc: "Kerberos service ticket requested (TGS-REQ)", significance: "Service access tracking, Kerberoasting detection", severity: "info" },
  { id: 4770, channel: "Security", desc: "Kerberos service ticket renewed", significance: "Ticket renewal, persistent access indicator", severity: "low" },
  { id: 4771, channel: "Security", desc: "Kerberos pre-authentication failed", significance: "Failed Kerberos auth, AS-REP roasting or password spray", severity: "medium" },

  // -- Security: System access --
  { id: 4717, channel: "Security", desc: "System security access granted to account", significance: "Elevated system access granted to user", severity: "medium" },
  { id: 4718, channel: "Security", desc: "System security access removed from account", significance: "System access revoked, may be cleanup after compromise", severity: "medium" },

  // -- Security: Audit policy --
  { id: 4719, channel: "Security", desc: "System audit policy changed", significance: "Audit evasion, attacker disabling logging", severity: "critical" },

  // -- Security: Account management --
  { id: 4720, channel: "Security", desc: "User account created", significance: "New account creation, backdoor account detection", severity: "medium" },
  { id: 4722, channel: "Security", desc: "User account enabled", significance: "Dormant account activated, potential unauthorized access", severity: "medium" },
  { id: 4723, channel: "Security", desc: "Attempt to change account password", significance: "Password change attempt, may be unauthorized", severity: "info" },
  { id: 4724, channel: "Security", desc: "Attempt to reset account password", significance: "Admin password reset, account takeover indicator", severity: "medium" },
  { id: 4725, channel: "Security", desc: "User account disabled", significance: "Account lockdown, may be defensive or malicious", severity: "medium" },
  { id: 4726, channel: "Security", desc: "User account deleted", significance: "Anti-forensics, cleanup of backdoor account", severity: "high" },
  { id: 4738, channel: "Security", desc: "User account changed", significance: "Account property modification, group membership change", severity: "medium" },
  { id: 4740, channel: "Security", desc: "User account locked out", significance: "Brute-force indicator, password spray detection", severity: "medium" },
  { id: 4767, channel: "Security", desc: "User account unlocked", significance: "Account recovery after lockout", severity: "info" },
  { id: 4781, channel: "Security", desc: "Account name changed", significance: "Account rename may indicate evasion", severity: "medium" },

  // -- Security: Computer accounts --
  { id: 4741, channel: "Security", desc: "Computer account created", significance: "New machine joined to domain, rogue system detection", severity: "info" },
  { id: 4742, channel: "Security", desc: "Computer account changed", significance: "Machine account modification, potential machine takeover", severity: "info" },
  { id: 4743, channel: "Security", desc: "Computer account deleted", significance: "Machine removed from domain", severity: "medium" },

  // -- Security: Group management --
  { id: 4727, channel: "Security", desc: "Security-enabled global group created", significance: "New security group, privilege management change", severity: "medium" },
  { id: 4728, channel: "Security", desc: "Member added to security-enabled global group", significance: "Group membership change, privilege escalation indicator", severity: "medium" },
  { id: 4729, channel: "Security", desc: "Member removed from security-enabled global group", significance: "Group membership change, access revocation", severity: "medium" },
  { id: 4730, channel: "Security", desc: "Security-enabled global group deleted", significance: "Security group removal", severity: "medium" },
  { id: 4731, channel: "Security", desc: "Security-enabled local group created", significance: "New local security group", severity: "medium" },
  { id: 4732, channel: "Security", desc: "Member added to security-enabled local group", significance: "Local group membership change, privilege escalation", severity: "medium" },
  { id: 4733, channel: "Security", desc: "Member removed from security-enabled local group", significance: "Member removed from local group", severity: "medium" },
  { id: 4734, channel: "Security", desc: "Security-enabled local group deleted", significance: "Local security group deleted", severity: "medium" },
  { id: 4735, channel: "Security", desc: "Security-enabled local group changed", significance: "Local group properties modified", severity: "medium" },
  { id: 4756, channel: "Security", desc: "Member added to security-enabled universal group", significance: "Universal group membership change, broad access grant", severity: "medium" },
  { id: 4757, channel: "Security", desc: "Member removed from security-enabled universal group", significance: "Universal group membership revoked", severity: "medium" },
  { id: 4764, channel: "Security", desc: "Group type changed", significance: "Group type conversion, may affect access scope", severity: "medium" },

  // -- Security: Credential validation --
  { id: 4776, channel: "Security", desc: "Domain controller attempted to validate credentials (NTLM)", significance: "NTLM authentication tracking, pass-the-hash detection", severity: "info" },

  // -- Security: Enumeration --
  { id: 4798, channel: "Security", desc: "User local group membership enumerated", significance: "Reconnaissance activity, user enumeration", severity: "medium" },
  { id: 4799, channel: "Security", desc: "Security-enabled local group membership enumerated", significance: "Reconnaissance of privileged group membership", severity: "medium" },

  // -- System events --
  { id: 7034, channel: "System", desc: "Service crashed unexpectedly", significance: "Service instability, crash exploitation, DoS indicator", severity: "high" },
  { id: 7036, channel: "System", desc: "Service entered a new state (started/stopped)", significance: "Service lifecycle tracking", severity: "info" },
  { id: 7040, channel: "System", desc: "Service start type changed", significance: "Persistence mechanism, service auto-start manipulation", severity: "medium" },
  { id: 7045, channel: "System", desc: "New service installed in the system", significance: "Service installation, persistence, malware dropper", severity: "high" },
  { id: 1000, channel: "Application", desc: "Application error (crash)", significance: "Application crash analysis, exploitation indicator", severity: "medium" },
  { id: 1001, channel: "Application", desc: "Windows Error Reporting (WER)", significance: "Detailed crash data, may reveal exploitation", severity: "low" },
  { id: 1002, channel: "Application", desc: "Application hang", significance: "Application unresponsive, potential DoS or resource exhaustion", severity: "low" },
  { id: 6005, channel: "System", desc: "Event Log service started", significance: "System boot indicator, uptime tracking", severity: "info" },
  { id: 6006, channel: "System", desc: "Event Log service stopped", significance: "Clean shutdown indicator", severity: "info" },
  { id: 6008, channel: "System", desc: "Unexpected system shutdown", significance: "Crash, power loss, forced shutdown -- forensic timeline marker", severity: "high" },
  { id: 6009, channel: "System", desc: "OS version information at boot", significance: "System identification, version tracking", severity: "low" },
  { id: 6013, channel: "System", desc: "System uptime in seconds", significance: "Uptime tracking, reboot timeline analysis", severity: "low" },
  { id: 104, channel: "System", desc: "Event log cleared", significance: "Anti-forensics -- attacker clearing tracks", severity: "critical" },
  { id: 1102, channel: "Security", desc: "Audit log was cleared", significance: "Anti-forensics -- security log specifically cleared", severity: "critical" },

  // -- PowerShell --
  { id: 4103, channel: "PowerShell", desc: "Module logging event", significance: "PowerShell module execution details", severity: "info" },
  { id: 4104, channel: "PowerShell", desc: "Script block logging", significance: "Full PowerShell script content captured, malware analysis", severity: "medium" },
  { id: 4105, channel: "PowerShell", desc: "Script execution started", significance: "PowerShell script execution began", severity: "info" },
  { id: 4106, channel: "PowerShell", desc: "Script execution stopped", significance: "PowerShell script execution ended", severity: "info" },
  { id: 400, channel: "PowerShell", desc: "Engine state changed to Available", significance: "PowerShell engine started, session initiated", severity: "info" },
  { id: 403, channel: "PowerShell", desc: "Engine state changed to Stopped", significance: "PowerShell engine stopped", severity: "info" },
  { id: 800, channel: "PowerShell", desc: "Pipeline execution details", significance: "Detailed PowerShell pipeline execution data", severity: "info" },

  // -- Sysmon --
  { id: 1, channel: "Sysmon", desc: "Process creation", significance: "Full command-line, hashes, parent process -- primary detection source", severity: "info" },
  { id: 2, channel: "Sysmon", desc: "File creation time changed", significance: "Timestomping detection, anti-forensics indicator", severity: "high" },
  { id: 3, channel: "Sysmon", desc: "Network connection detected", significance: "Outbound/inbound connections, C2 communication detection", severity: "info" },
  { id: 4, channel: "Sysmon", desc: "Sysmon service state changed", significance: "Sysmon itself started/stopped, potential tampering", severity: "medium" },
  { id: 5, channel: "Sysmon", desc: "Process terminated", significance: "Process lifecycle end, correlate with creation (ID 1)", severity: "low" },
  { id: 6, channel: "Sysmon", desc: "Driver loaded", significance: "Kernel driver loading, rootkit detection", severity: "medium" },
  { id: 7, channel: "Sysmon", desc: "Image loaded (DLL)", significance: "DLL loading, DLL injection/sideloading detection", severity: "info" },
  { id: 8, channel: "Sysmon", desc: "CreateRemoteThread detected", significance: "Code injection, process hollowing, shellcode injection", severity: "high" },
  { id: 9, channel: "Sysmon", desc: "RawAccessRead detected", significance: "Direct disk read bypassing filesystem, credential dumping", severity: "high" },
  { id: 10, channel: "Sysmon", desc: "Process accessed another process", significance: "Process injection, credential dumping (e.g. LSASS access)", severity: "high" },
  { id: 11, channel: "Sysmon", desc: "File created", significance: "File creation tracking, malware drop detection", severity: "info" },
  { id: 12, channel: "Sysmon", desc: "Registry object added or deleted", significance: "Registry persistence, configuration tampering", severity: "medium" },
  { id: 13, channel: "Sysmon", desc: "Registry value set", significance: "Registry modification, persistence/config changes", severity: "medium" },
  { id: 14, channel: "Sysmon", desc: "Registry object renamed", significance: "Registry key/value rename, evasion technique", severity: "medium" },
  { id: 15, channel: "Sysmon", desc: "FileCreateStreamHash (ADS)", significance: "Alternate Data Stream creation, data hiding", severity: "high" },
  { id: 16, channel: "Sysmon", desc: "Sysmon configuration changed", significance: "Sysmon config modified, potential evasion", severity: "high" },
  { id: 17, channel: "Sysmon", desc: "Named pipe created", significance: "IPC channel creation, C2 named pipe detection", severity: "medium" },
  { id: 18, channel: "Sysmon", desc: "Named pipe connected", significance: "IPC connection, lateral movement via named pipes", severity: "medium" },
  { id: 19, channel: "Sysmon", desc: "WMI event filter activity detected", significance: "WMI persistence, event subscription backdoor", severity: "high" },
  { id: 20, channel: "Sysmon", desc: "WMI event consumer activity detected", significance: "WMI persistence consumer, action trigger for backdoor", severity: "high" },
  { id: 21, channel: "Sysmon", desc: "WMI event consumer-to-filter binding", significance: "WMI persistence binding, completing the subscription chain", severity: "high" },
  { id: 22, channel: "Sysmon", desc: "DNS query event", significance: "DNS resolution tracking, C2 domain detection, DNS tunneling", severity: "info" },
  { id: 23, channel: "Sysmon", desc: "File deleted (archived)", significance: "File deletion with archival, data destruction tracking", severity: "medium" },
  { id: 24, channel: "Sysmon", desc: "Clipboard content changed", significance: "Clipboard monitoring, data exfiltration via clipboard", severity: "medium" },
  { id: 25, channel: "Sysmon", desc: "Process tampering detected", significance: "Process hollowing, herpaderping, ghosting detection", severity: "critical" },
  { id: 26, channel: "Sysmon", desc: "File delete detected (logged)", significance: "File deletion event logged without archival", severity: "medium" },
  { id: 255, channel: "Sysmon", desc: "Sysmon error", significance: "Sysmon internal error, may indicate evasion attempt", severity: "medium" },

  // -- Task Scheduler --
  { id: 106, channel: "TaskScheduler", desc: "Scheduled task registered", significance: "New task creation, persistence mechanism", severity: "medium" },
  { id: 140, channel: "TaskScheduler", desc: "Scheduled task updated", significance: "Task modification, potential tampering", severity: "medium" },
  { id: 141, channel: "TaskScheduler", desc: "Scheduled task removed", significance: "Task deletion, cleanup after execution", severity: "medium" },
  { id: 200, channel: "TaskScheduler", desc: "Scheduled task action started", significance: "Task execution began", severity: "info" },
  { id: 201, channel: "TaskScheduler", desc: "Scheduled task action completed", significance: "Task execution finished, check result code", severity: "info" },

  // -- Windows Defender --
  { id: 1006, channel: "Defender", desc: "Malware or unwanted software detected", significance: "Antimalware detection, initial alert", severity: "high" },
  { id: 1007, channel: "Defender", desc: "Action taken against malware", significance: "Defender response action (quarantine/remove/allow)", severity: "medium" },
  { id: 1008, channel: "Defender", desc: "Action against malware failed", significance: "Failed remediation, malware still active", severity: "critical" },
  { id: 1116, channel: "Defender", desc: "Antimalware detection event", significance: "Detailed malware detection with threat name/path", severity: "high" },
  { id: 1117, channel: "Defender", desc: "Antimalware action taken", significance: "Defender took action on detected threat", severity: "medium" },
  { id: 5001, channel: "Defender", desc: "Real-time protection disabled", significance: "AV disabled, attacker disabling defenses", severity: "critical" },
  { id: 5010, channel: "Defender", desc: "Scanning for malware disabled", significance: "Scan capability disabled", severity: "high" },
  { id: 5012, channel: "Defender", desc: "Scanning for viruses disabled", significance: "Virus scanning specifically disabled", severity: "high" },

  // -- Windows Firewall --
  { id: 2004, channel: "Firewall", desc: "Firewall rule added", significance: "New firewall rule, potential hole opened", severity: "medium" },
  { id: 2005, channel: "Firewall", desc: "Firewall rule modified", significance: "Existing firewall rule changed", severity: "medium" },
  { id: 2006, channel: "Firewall", desc: "Firewall rule deleted", significance: "Firewall rule removed, defensive gap", severity: "medium" },
  { id: 2033, channel: "Firewall", desc: "Firewall profile set to off", significance: "Firewall profile disabled, defensive evasion", severity: "critical" },

  // -- Additional Security events --
  { id: 4656, channel: "Security", desc: "Handle to an object was requested", significance: "Object access attempt, file/registry auditing", severity: "low" },
  { id: 4657, channel: "Security", desc: "Registry value modified", significance: "Registry modification tracking", severity: "info" },
  { id: 4660, channel: "Security", desc: "Object was deleted", significance: "File/object deletion tracking", severity: "info" },
  { id: 4663, channel: "Security", desc: "Attempt to access an object", significance: "File access auditing, data exfiltration tracking", severity: "info" },
  { id: 4670, channel: "Security", desc: "Permissions on an object changed", significance: "ACL modification, access control tampering", severity: "medium" },
  { id: 4907, channel: "Security", desc: "Auditing settings on object changed", significance: "SACL modification, audit evasion", severity: "high" },
  { id: 4946, channel: "Security", desc: "Windows Firewall exception list changed", significance: "Firewall rule added via security audit", severity: "medium" },
  { id: 4950, channel: "Security", desc: "Windows Firewall setting changed", significance: "Firewall configuration modification", severity: "medium" },
  { id: 4954, channel: "Security", desc: "Windows Firewall Group Policy changed", significance: "Firewall GPO-level changes", severity: "medium" },
  { id: 5025, channel: "Security", desc: "Windows Firewall service stopped", significance: "Firewall service disabled, defensive gap", severity: "critical" },
  { id: 5140, channel: "Security", desc: "Network share object was accessed", significance: "File share access, lateral movement tracking", severity: "info" },
  { id: 5145, channel: "Security", desc: "Network share object checked for access", significance: "Share access check with detailed permissions", severity: "info" },
  { id: 5156, channel: "Security", desc: "Windows Filtering Platform allowed connection", significance: "Outbound/inbound connection allowed", severity: "low" },
  { id: 5157, channel: "Security", desc: "Windows Filtering Platform blocked connection", significance: "Connection blocked by WFP, may indicate attack attempts", severity: "info" },
];

// ---------------------------------------------------------------------------
// SECTION 3: BROWSER ARTIFACTS DATA
// ---------------------------------------------------------------------------

const BROWSER_ARTIFACTS = [
  {
    name: "Google Chrome",
    paths: [
      { artifact: "History", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History", mac: "~/Library/Application Support/Google/Chrome/Default/History", linux: "~/.config/google-chrome/Default/History" },
      { artifact: "Cookies", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies", mac: "~/Library/Application Support/Google/Chrome/Default/Cookies", linux: "~/.config/google-chrome/Default/Cookies" },
      { artifact: "Cache", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data", mac: "~/Library/Caches/Google/Chrome/Default/Cache/Cache_Data", linux: "~/.config/google-chrome/Default/Cache/Cache_Data" },
      { artifact: "Downloads", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History (downloads table)", mac: "~/Library/Application Support/Google/Chrome/Default/History", linux: "~/.config/google-chrome/Default/History" },
      { artifact: "Bookmarks", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Bookmarks", mac: "~/Library/Application Support/Google/Chrome/Default/Bookmarks", linux: "~/.config/google-chrome/Default/Bookmarks" },
      { artifact: "Login Data", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data", mac: "~/Library/Application Support/Google/Chrome/Default/Login Data", linux: "~/.config/google-chrome/Default/Login Data" },
      { artifact: "Extensions", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Extensions\\", mac: "~/Library/Application Support/Google/Chrome/Default/Extensions/", linux: "~/.config/google-chrome/Default/Extensions/" },
      { artifact: "Sessions", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Sessions\\", mac: "~/Library/Application Support/Google/Chrome/Default/Sessions/", linux: "~/.config/google-chrome/Default/Sessions/" },
      { artifact: "Current Session", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Current Session", mac: "~/Library/Application Support/Google/Chrome/Default/Current Session", linux: "~/.config/google-chrome/Default/Current Session" },
      { artifact: "Current Tabs", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Current Tabs", mac: "~/Library/Application Support/Google/Chrome/Default/Current Tabs", linux: "~/.config/google-chrome/Default/Current Tabs" },
      { artifact: "Autofill / Web Data", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Web Data", mac: "~/Library/Application Support/Google/Chrome/Default/Web Data", linux: "~/.config/google-chrome/Default/Web Data" },
      { artifact: "Preferences", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Preferences", mac: "~/Library/Application Support/Google/Chrome/Default/Preferences", linux: "~/.config/google-chrome/Default/Preferences" },
      { artifact: "Top Sites", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Top Sites", mac: "~/Library/Application Support/Google/Chrome/Default/Top Sites", linux: "~/.config/google-chrome/Default/Top Sites" },
      { artifact: "Favicons", win: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Favicons", mac: "~/Library/Application Support/Google/Chrome/Default/Favicons", linux: "~/.config/google-chrome/Default/Favicons" },
    ],
  },
  {
    name: "Mozilla Firefox",
    paths: [
      { artifact: "History", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\places.sqlite", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/places.sqlite", linux: "~/.mozilla/firefox/<profile>/places.sqlite" },
      { artifact: "Cookies", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\cookies.sqlite", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/cookies.sqlite", linux: "~/.mozilla/firefox/<profile>/cookies.sqlite" },
      { artifact: "Cache", win: "%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\cache2\\entries\\", mac: "~/Library/Caches/Firefox/Profiles/<profile>/cache2/entries/", linux: "~/.cache/mozilla/firefox/<profile>/cache2/entries/" },
      { artifact: "Downloads", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\places.sqlite (moz_annos table)", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/places.sqlite", linux: "~/.mozilla/firefox/<profile>/places.sqlite" },
      { artifact: "Bookmarks", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\places.sqlite (moz_bookmarks)", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/places.sqlite", linux: "~/.mozilla/firefox/<profile>/places.sqlite" },
      { artifact: "Login Data", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\logins.json + key4.db", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/logins.json + key4.db", linux: "~/.mozilla/firefox/<profile>/logins.json + key4.db" },
      { artifact: "Extensions", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\extensions\\", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/extensions/", linux: "~/.mozilla/firefox/<profile>/extensions/" },
      { artifact: "Sessions", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\sessionstore-backups\\recovery.jsonlz4", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/sessionstore-backups/recovery.jsonlz4", linux: "~/.mozilla/firefox/<profile>/sessionstore-backups/recovery.jsonlz4" },
      { artifact: "Form History", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\formhistory.sqlite", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/formhistory.sqlite", linux: "~/.mozilla/firefox/<profile>/formhistory.sqlite" },
      { artifact: "Permissions", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\permissions.sqlite", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/permissions.sqlite", linux: "~/.mozilla/firefox/<profile>/permissions.sqlite" },
      { artifact: "Preferences", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\prefs.js", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/prefs.js", linux: "~/.mozilla/firefox/<profile>/prefs.js" },
      { artifact: "Cert Store", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\cert9.db", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/cert9.db", linux: "~/.mozilla/firefox/<profile>/cert9.db" },
      { artifact: "Favicons", win: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\favicons.sqlite", mac: "~/Library/Application Support/Firefox/Profiles/<profile>/favicons.sqlite", linux: "~/.mozilla/firefox/<profile>/favicons.sqlite" },
    ],
  },
  {
    name: "Microsoft Edge (Chromium)",
    paths: [
      { artifact: "History", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History", mac: "~/Library/Application Support/Microsoft Edge/Default/History", linux: "~/.config/microsoft-edge/Default/History" },
      { artifact: "Cookies", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cookies", mac: "~/Library/Application Support/Microsoft Edge/Default/Cookies", linux: "~/.config/microsoft-edge/Default/Cookies" },
      { artifact: "Cache", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache\\Cache_Data", mac: "~/Library/Caches/Microsoft Edge/Default/Cache/Cache_Data", linux: "~/.config/microsoft-edge/Default/Cache/Cache_Data" },
      { artifact: "Downloads", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History (downloads table)", mac: "~/Library/Application Support/Microsoft Edge/Default/History", linux: "~/.config/microsoft-edge/Default/History" },
      { artifact: "Bookmarks", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Bookmarks", mac: "~/Library/Application Support/Microsoft Edge/Default/Bookmarks", linux: "~/.config/microsoft-edge/Default/Bookmarks" },
      { artifact: "Login Data", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data", mac: "~/Library/Application Support/Microsoft Edge/Default/Login Data", linux: "~/.config/microsoft-edge/Default/Login Data" },
      { artifact: "Extensions", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Extensions\\", mac: "~/Library/Application Support/Microsoft Edge/Default/Extensions/", linux: "~/.config/microsoft-edge/Default/Extensions/" },
      { artifact: "Sessions", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Sessions\\", mac: "~/Library/Application Support/Microsoft Edge/Default/Sessions/", linux: "~/.config/microsoft-edge/Default/Sessions/" },
      { artifact: "Autofill / Web Data", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Web Data", mac: "~/Library/Application Support/Microsoft Edge/Default/Web Data", linux: "~/.config/microsoft-edge/Default/Web Data" },
      { artifact: "Preferences", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Preferences", mac: "~/Library/Application Support/Microsoft Edge/Default/Preferences", linux: "~/.config/microsoft-edge/Default/Preferences" },
      { artifact: "Collections", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Collections\\collectionsSQLite", mac: "~/Library/Application Support/Microsoft Edge/Default/Collections/collectionsSQLite", linux: "~/.config/microsoft-edge/Default/Collections/collectionsSQLite" },
      { artifact: "Top Sites", win: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Top Sites", mac: "~/Library/Application Support/Microsoft Edge/Default/Top Sites", linux: "~/.config/microsoft-edge/Default/Top Sites" },
    ],
  },
  {
    name: "Apple Safari",
    paths: [
      { artifact: "History", win: "N/A", mac: "~/Library/Safari/History.db", linux: "N/A" },
      { artifact: "Cookies", win: "N/A", mac: "~/Library/Cookies/Cookies.binarycookies", linux: "N/A" },
      { artifact: "Cache", win: "N/A", mac: "~/Library/Caches/com.apple.Safari/Cache.db", linux: "N/A" },
      { artifact: "Downloads", win: "N/A", mac: "~/Library/Safari/Downloads.plist", linux: "N/A" },
      { artifact: "Bookmarks", win: "N/A", mac: "~/Library/Safari/Bookmarks.plist", linux: "N/A" },
      { artifact: "Login Data", win: "N/A", mac: "Keychain Access: ~/Library/Keychains/login.keychain-db", linux: "N/A" },
      { artifact: "Extensions", win: "N/A", mac: "~/Library/Safari/Extensions/", linux: "N/A" },
      { artifact: "Sessions / Tabs", win: "N/A", mac: "~/Library/Safari/LastSession.plist", linux: "N/A" },
      { artifact: "Form Values", win: "N/A", mac: "~/Library/Safari/Form Values (encrypted, in Keychain)", linux: "N/A" },
      { artifact: "Preferences", win: "N/A", mac: "~/Library/Preferences/com.apple.Safari.plist", linux: "N/A" },
      { artifact: "Top Sites", win: "N/A", mac: "~/Library/Safari/TopSites.plist", linux: "N/A" },
      { artifact: "Favicons", win: "N/A", mac: "~/Library/Safari/Favicon Cache/favicons.db", linux: "N/A" },
      { artifact: "Cloud Tabs", win: "N/A", mac: "~/Library/Safari/CloudTabs.db", linux: "N/A" },
    ],
  },
];

// ---------------------------------------------------------------------------
// SECTION 4: TAB RENDER FUNCTIONS
// ---------------------------------------------------------------------------

// ---- Tab 1: File Signatures ----

function renderFileSigs(root) {
  root.innerHTML = `
    <h2 class="pg-h2">File Signature Identifier</h2>
    <p class="muted">Enter hex bytes (e.g. 89504E47) to identify a file type by its magic bytes.
    The database contains ${FILE_SIGS.length} known signatures.</p>
    <div class="tk-row" style="gap:8px;display:flex;align-items:center;flex-wrap:wrap">
      <input class="tk-f" id="fsig-input" type="text" placeholder="Enter hex bytes, e.g. 504B0304 or FFD8FF"
        style="flex:1;min-width:200px">
      <button class="btn sm" id="fsig-search">Search / Identify</button>
    </div>
    <div id="fsig-results" style="margin-top:14px"></div>
    <h2 class="pg-h2" style="margin-top:28px">Full Signature Reference (${FILE_SIGS.length} entries)</h2>
    <div style="overflow-x:auto">
      <table id="fsig-table" style="width:100%;border-collapse:collapse">
        <thead>
          <tr>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Hex Bytes</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Extension</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">MIME Type</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Description</th>
          </tr>
        </thead>
        <tbody id="fsig-tbody"></tbody>
      </table>
    </div>`;

  const tbody = root.querySelector("#fsig-tbody");
  const resultsDiv = root.querySelector("#fsig-results");
  const input = root.querySelector("#fsig-input");
  const searchBtn = root.querySelector("#fsig-search");

  // Render the full reference table
  function renderFullTable(entries) {
    tbody.innerHTML = entries.map((s) => `<tr>
      <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-family:monospace;font-size:0.85em">${escapeHtml(s.bytes)}</td>
      <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">.${escapeHtml(s.ext)}</td>
      <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-size:0.85em">${escapeHtml(s.mime)}</td>
      <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">${escapeHtml(s.desc)}</td>
    </tr>`).join("");
  }

  renderFullTable(FILE_SIGS);

  function doSearch() {
    const raw = input.value.trim().replace(/[\s,\-]+/g, "").replace(/^0x/i, "");
    if (!raw) {
      resultsDiv.innerHTML = `<p class="muted">Enter hex bytes above to search.</p>`;
      renderFullTable(FILE_SIGS);
      return;
    }
    if (!/^[0-9a-fA-F]*$/.test(raw)) {
      resultsDiv.innerHTML = `<p style="color:var(--red,#f44)">Invalid hex characters. Use 0-9 and A-F only.</p>`;
      return;
    }
    const upper = raw.toUpperCase();
    const matches = FILE_SIGS.filter((s) => s.bytes.toUpperCase().startsWith(upper) || upper.startsWith(s.bytes.toUpperCase()));
    if (matches.length === 0) {
      resultsDiv.innerHTML = `<p class="muted">No matching signatures found for <code style="font-family:monospace">${escapeHtml(raw)}</code>.</p>`;
    } else {
      resultsDiv.innerHTML = `<p style="margin-bottom:8px"><strong>${matches.length} match${matches.length > 1 ? "es" : ""} found:</strong></p>
        <table style="width:100%;border-collapse:collapse">
          <thead><tr>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--accent,#0af)">Hex Bytes</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--accent,#0af)">Extension</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--accent,#0af)">MIME</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--accent,#0af)">Description</th>
          </tr></thead>
          <tbody>${matches.map((s) => `<tr>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-family:monospace">${escapeHtml(s.bytes)}</td>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">.${escapeHtml(s.ext)}</td>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-size:0.85em">${escapeHtml(s.mime)}</td>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">${escapeHtml(s.desc)}</td>
          </tr>`).join("")}</tbody>
        </table>`;
    }
    // Also filter the full table to show matches
    renderFullTable(matches.length > 0 ? matches : FILE_SIGS);
  }

  searchBtn.addEventListener("click", doSearch);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch(); });
}

// ---- Tab 2: Hex Viewer ----

function renderHexViewer(root) {
  root.innerHTML = `
    <h2 class="pg-h2">Hex Viewer / Hex Dump</h2>
    <p class="muted">Paste hex data or raw text below, then click Parse to produce a formatted hex dump
    with offsets, hex pairs, and ASCII column.</p>
    <div class="tk-row" style="gap:8px;display:flex;align-items:center;flex-wrap:wrap;margin-bottom:8px">
      <label style="display:inline-flex;align-items:center;gap:6px">
        <input type="radio" name="hexmode" value="hex" checked> Hex Input
      </label>
      <label style="display:inline-flex;align-items:center;gap:6px">
        <input type="radio" name="hexmode" value="text"> Text Input
      </label>
      <button class="btn sm" id="hex-parse">Parse</button>
      <button class="btn sm ghost" id="hex-clear">Clear</button>
    </div>
    <textarea class="tk-in" id="hex-input" rows="6"
      placeholder="Paste hex bytes (e.g. 48656C6C6F20576F726C64) or switch to text mode and paste raw text"></textarea>
    <pre class="tk-out mono" id="hex-output" style="white-space:pre;overflow-x:auto;font-size:0.82em;line-height:1.5"></pre>`;

  const inputEl = root.querySelector("#hex-input");
  const outputEl = root.querySelector("#hex-output");
  const parseBtn = root.querySelector("#hex-parse");
  const clearBtn = root.querySelector("#hex-clear");
  const modeRadios = root.querySelectorAll('input[name="hexmode"]');

  function getMode() {
    for (const r of modeRadios) { if (r.checked) return r.value; }
    return "hex";
  }

  // Update placeholder when mode changes
  for (const r of modeRadios) {
    r.addEventListener("change", () => {
      if (getMode() === "hex") {
        inputEl.placeholder = "Paste hex bytes (e.g. 48656C6C6F20576F726C64)";
      } else {
        inputEl.placeholder = "Paste raw text (will be converted to hex and displayed as hex dump)";
      }
    });
  }

  function parseHexInput(hexStr) {
    const clean = hexStr.replace(/[\s,\-:;|]+/g, "").replace(/^0x/i, "");
    if (clean.length === 0) throw new Error("No hex data provided");
    if (clean.length % 2 !== 0) throw new Error("Hex string must have an even number of digits (got " + clean.length + ")");
    if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error("Invalid hex characters detected. Use 0-9 and A-F only.");
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function textToBytes(str) {
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      bytes[i] = str.charCodeAt(i) & 0xFF;
    }
    return bytes;
  }

  function formatHexDump(bytes) {
    if (bytes.length === 0) return "(empty)";
    const lines = [];
    const totalLines = Math.ceil(bytes.length / 16);
    // Header
    lines.push("Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |ASCII           |");
    lines.push("-".repeat(80));
    for (let row = 0; row < totalLines; row++) {
      const offset = row * 16;
      const offsetStr = offset.toString(16).toUpperCase().padStart(8, "0");
      const hexParts = [];
      let ascii = "";
      for (let col = 0; col < 16; col++) {
        const idx = offset + col;
        if (idx < bytes.length) {
          hexParts.push(bytes[idx].toString(16).toUpperCase().padStart(2, "0"));
          const ch = bytes[idx];
          ascii += (ch >= 0x20 && ch <= 0x7E) ? String.fromCharCode(ch) : ".";
        } else {
          hexParts.push("  ");
          ascii += " ";
        }
      }
      // Group hex pairs: first 8, then next 8 with an extra space separator
      const left = hexParts.slice(0, 8).join(" ");
      const right = hexParts.slice(8, 16).join(" ");
      lines.push(`${offsetStr}  ${left}  ${right}  |${ascii}|`);
    }
    lines.push("");
    lines.push(`Total: ${bytes.length} byte${bytes.length !== 1 ? "s" : ""} (0x${bytes.length.toString(16).toUpperCase()})`);
    return lines.join("\n");
  }

  parseBtn.addEventListener("click", () => {
    try {
      const rawInput = inputEl.value;
      if (!rawInput.trim()) {
        outputEl.textContent = "No input provided.";
        return;
      }
      let bytes;
      if (getMode() === "hex") {
        bytes = parseHexInput(rawInput);
      } else {
        bytes = textToBytes(rawInput);
      }
      outputEl.textContent = formatHexDump(bytes);
    } catch (err) {
      outputEl.textContent = "Error: " + err.message;
    }
  });

  clearBtn.addEventListener("click", () => {
    inputEl.value = "";
    outputEl.textContent = "";
  });
}

// ---- Tab 3: Timestamp Converter ----

function renderTimestamps(root) {
  root.innerHTML = `
    <h2 class="pg-h2">Forensic Timestamp Converter</h2>
    <p class="muted">Enter a timestamp value and select the input format (or use auto-detect).
    All known forensic timestamp formats will be computed and displayed.</p>
    <div class="tk-row" style="gap:8px;display:flex;align-items:center;flex-wrap:wrap;margin-bottom:8px">
      <input class="tk-f" id="ts-input" type="text" placeholder="Enter timestamp value, e.g. 1700000000 or 2024-01-15T12:00:00Z"
        style="flex:1;min-width:200px">
      <select class="tk-f" id="ts-format" style="min-width:180px">
        <option value="auto">Auto-detect</option>
        <option value="unix">Unix Epoch (seconds)</option>
        <option value="unix_ms">Unix Epoch (milliseconds)</option>
        <option value="filetime">Windows FILETIME</option>
        <option value="mac_abs">Mac Absolute Time / Core Data</option>
        <option value="ldap">LDAP / Active Directory</option>
        <option value="chrome">Chrome / WebKit</option>
        <option value="iso8601">ISO 8601</option>
        <option value="rfc2822">RFC 2822</option>
        <option value="hfs">HFS+ (seconds since 1904)</option>
        <option value="ntp">NTP (seconds since 1900)</option>
        <option value="gps">GPS (seconds since 1980-01-06)</option>
      </select>
      <button class="btn sm" id="ts-convert">Convert</button>
    </div>
    <div id="ts-results" style="margin-top:14px"></div>
    <div style="margin-top:18px">
      <h2 class="pg-h2">Reference: Epoch Offsets</h2>
      <table style="width:100%;border-collapse:collapse;margin-top:6px">
        <thead><tr>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Format</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Epoch Start</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Unit</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Offset from Unix (seconds)</th>
        </tr></thead>
        <tbody>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Unix Epoch</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">1970-01-01 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Seconds</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">0</td></tr>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Unix Epoch (ms)</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">1970-01-01 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Milliseconds</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">0</td></tr>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Windows FILETIME</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">1601-01-01 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">100-nanosecond intervals</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">-11644473600</td></tr>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Mac Absolute Time</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">2001-01-01 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Seconds</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">+978307200</td></tr>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">LDAP / AD</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">1601-01-01 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">100-nanosecond intervals</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">-11644473600</td></tr>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Chrome / WebKit</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">1601-01-01 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Microseconds</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">-11644473600</td></tr>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">HFS+</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">1904-01-01 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Seconds</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">-2082844800</td></tr>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">NTP</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">1900-01-01 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Seconds</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">-2208988800</td></tr>
          <tr><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">GPS</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">1980-01-06 00:00:00 UTC</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">Seconds</td><td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">+315964800</td></tr>
        </tbody>
      </table>
    </div>`;

  const input = root.querySelector("#ts-input");
  const formatSel = root.querySelector("#ts-format");
  const convertBtn = root.querySelector("#ts-convert");
  const resultsDiv = root.querySelector("#ts-results");

  // Epoch offset constants (seconds relative to Unix epoch)
  const FILETIME_EPOCH_OFFSET = 11644473600; // seconds between 1601-01-01 and 1970-01-01
  const MAC_ABS_EPOCH_OFFSET = 978307200;    // seconds between 1970-01-01 and 2001-01-01
  const HFS_EPOCH_OFFSET = 2082844800;       // seconds between 1904-01-01 and 1970-01-01
  const NTP_EPOCH_OFFSET = 2208988800;       // seconds between 1900-01-01 and 1970-01-01
  const GPS_EPOCH_OFFSET = 315964800;        // seconds between 1970-01-01 and 1980-01-06

  // Convert any supported format to Unix epoch seconds (as a number)
  function toUnixSeconds(value, format) {
    const v = value.trim();

    if (format === "auto") {
      format = detectFormat(v);
    }

    switch (format) {
      case "unix": {
        const n = parseFloat(v);
        if (isNaN(n)) throw new Error("Invalid numeric value");
        return n;
      }
      case "unix_ms": {
        const n = parseFloat(v);
        if (isNaN(n)) throw new Error("Invalid numeric value");
        return n / 1000;
      }
      case "filetime": {
        // 100-nanosecond intervals since 1601-01-01
        const n = parseBigIntSafe(v);
        // Convert to seconds: divide by 10,000,000, then subtract epoch offset
        return Number(n / 10000000n) - FILETIME_EPOCH_OFFSET;
      }
      case "mac_abs": {
        const n = parseFloat(v);
        if (isNaN(n)) throw new Error("Invalid numeric value");
        // Mac absolute time is seconds since 2001-01-01
        return n + MAC_ABS_EPOCH_OFFSET;
      }
      case "ldap": {
        // Same epoch as FILETIME (1601), 100-nanosecond intervals
        const n = parseBigIntSafe(v);
        return Number(n / 10000000n) - FILETIME_EPOCH_OFFSET;
      }
      case "chrome": {
        // Microseconds since 1601-01-01
        const n = parseBigIntSafe(v);
        return Number(n / 1000000n) - FILETIME_EPOCH_OFFSET;
      }
      case "iso8601": {
        const d = new Date(v);
        if (isNaN(d.getTime())) throw new Error("Invalid ISO 8601 date string");
        return d.getTime() / 1000;
      }
      case "rfc2822": {
        const d = new Date(v);
        if (isNaN(d.getTime())) throw new Error("Invalid RFC 2822 date string");
        return d.getTime() / 1000;
      }
      case "hfs": {
        const n = parseFloat(v);
        if (isNaN(n)) throw new Error("Invalid numeric value");
        // HFS+ seconds since 1904-01-01
        return n - HFS_EPOCH_OFFSET;
      }
      case "ntp": {
        const n = parseFloat(v);
        if (isNaN(n)) throw new Error("Invalid numeric value");
        // NTP seconds since 1900-01-01
        return n - NTP_EPOCH_OFFSET;
      }
      case "gps": {
        const n = parseFloat(v);
        if (isNaN(n)) throw new Error("Invalid numeric value");
        // GPS seconds since 1980-01-06
        return n + GPS_EPOCH_OFFSET;
      }
      default:
        throw new Error("Unknown format: " + format);
    }
  }

  function parseBigIntSafe(s) {
    const clean = s.trim();
    if (!/^-?\d+$/.test(clean)) throw new Error("Expected an integer value for this format");
    return BigInt(clean);
  }

  function detectFormat(v) {
    // ISO 8601 pattern
    if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(v)) return "iso8601";
    // RFC 2822 pattern (starts with day name or month)
    if (/^[A-Za-z]{3},?\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}/.test(v)) return "rfc2822";
    // If it contains a date-like separator, try ISO
    if (/^\d{4}-\d{2}-\d{2}/.test(v)) return "iso8601";

    // Numeric values: detect by magnitude
    const n = parseFloat(v);
    if (isNaN(n)) throw new Error("Cannot auto-detect format. Please select a format manually.");

    const absn = Math.abs(n);
    // FILETIME / LDAP values are very large (18-digit numbers, ~130000000000000000 range)
    if (absn > 1e16) {
      // Could be FILETIME, LDAP, or Chrome
      // Chrome values are around 13 digits * 1e6 = ~1.3e16
      // FILETIME/LDAP are around 1.3e17
      if (absn > 1e17) return "filetime"; // FILETIME/LDAP range
      return "chrome"; // Chrome/WebKit range
    }
    // Unix milliseconds are 13 digits (~1.7e12)
    if (absn > 1e12) return "unix_ms";
    // HFS+ and NTP values can be > ~2e9 for current dates
    // Unix seconds for current dates are ~1.7e9
    // Mac absolute time for current dates are ~7e8
    // GPS for current dates are ~1.4e9
    // Default to unix seconds for reasonable range
    if (absn > 1e8) return "unix";
    // Small values are ambiguous -- default to unix
    return "unix";
  }

  function formatDate(unixSec) {
    const d = new Date(unixSec * 1000);
    if (isNaN(d.getTime())) return "(invalid date)";
    return d.toUTCString() + " (" + d.toISOString() + ")";
  }

  function computeAllFormats(unixSec) {
    const ms = unixSec * 1000;
    const d = new Date(ms);
    const readable = isNaN(d.getTime()) ? "(invalid date)" : d.toUTCString();
    const isoStr = isNaN(d.getTime()) ? "(invalid)" : d.toISOString();
    const rfc = isNaN(d.getTime()) ? "(invalid)" : d.toUTCString();

    // FILETIME: (unixSec + 11644473600) * 10000000
    const filetimeBig = BigInt(Math.round(unixSec + FILETIME_EPOCH_OFFSET)) * 10000000n;
    // Chrome: (unixSec + 11644473600) * 1000000
    const chromeBig = BigInt(Math.round(unixSec + FILETIME_EPOCH_OFFSET)) * 1000000n;
    // Mac absolute time: unixSec - 978307200
    const macAbs = unixSec - MAC_ABS_EPOCH_OFFSET;
    // HFS+: unixSec + 2082844800
    const hfs = unixSec + HFS_EPOCH_OFFSET;
    // NTP: unixSec + 2208988800
    const ntp = unixSec + NTP_EPOCH_OFFSET;
    // GPS: unixSec - 315964800
    const gps = unixSec - GPS_EPOCH_OFFSET;

    return [
      { label: "Human Readable (UTC)", value: readable, extra: "" },
      { label: "Unix Epoch (seconds)", value: String(Math.round(unixSec)), extra: formatDate(unixSec) },
      { label: "Unix Epoch (milliseconds)", value: String(Math.round(ms)), extra: "" },
      { label: "ISO 8601", value: isoStr, extra: "" },
      { label: "RFC 2822", value: rfc, extra: "" },
      { label: "Windows FILETIME", value: filetimeBig.toString(), extra: "100-ns intervals since 1601-01-01" },
      { label: "LDAP / Active Directory", value: filetimeBig.toString(), extra: "Same epoch/unit as FILETIME" },
      { label: "Chrome / WebKit", value: chromeBig.toString(), extra: "Microseconds since 1601-01-01" },
      { label: "Mac Absolute Time / Core Data", value: String(Math.round(macAbs)), extra: "Seconds since 2001-01-01" },
      { label: "HFS+ (Classic Mac)", value: String(Math.round(hfs)), extra: "Seconds since 1904-01-01" },
      { label: "NTP Timestamp", value: String(Math.round(ntp)), extra: "Seconds since 1900-01-01" },
      { label: "GPS Time", value: String(Math.round(gps)), extra: "Seconds since 1980-01-06" },
    ];
  }

  convertBtn.addEventListener("click", () => {
    const v = input.value.trim();
    if (!v) {
      resultsDiv.innerHTML = `<p class="muted">Enter a timestamp value above.</p>`;
      return;
    }
    try {
      const fmt = formatSel.value;
      const detectedFmt = fmt === "auto" ? detectFormat(v) : fmt;
      const unixSec = toUnixSeconds(v, fmt);
      const all = computeAllFormats(unixSec);
      resultsDiv.innerHTML = `
        <p style="margin-bottom:8px"><strong>Detected format:</strong> ${escapeHtml(detectedFmt)}
        &nbsp;|&nbsp; <strong>Input:</strong> <code style="font-family:monospace">${escapeHtml(v)}</code></p>
        <table style="width:100%;border-collapse:collapse">
          <thead><tr>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--accent,#0af)">Format</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--accent,#0af)">Value</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--accent,#0af)">Note</th>
          </tr></thead>
          <tbody>${all.map((r) => `<tr>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);white-space:nowrap">${escapeHtml(r.label)}</td>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-family:monospace;word-break:break-all">${escapeHtml(r.value)}</td>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-size:0.85em" class="muted">${escapeHtml(r.extra)}</td>
          </tr>`).join("")}</tbody>
        </table>`;
    } catch (err) {
      resultsDiv.innerHTML = `<p style="color:var(--red,#f44)">Error: ${escapeHtml(err.message)}</p>`;
    }
  });

  input.addEventListener("keydown", (e) => { if (e.key === "Enter") convertBtn.click(); });
}

// ---- Tab 4: Windows Event IDs ----

function renderWinEvents(root) {
  const severityColors = {
    critical: "#f44",
    high: "#f80",
    medium: "#fb0",
    info: "#0af",
    low: "#888",
  };

  root.innerHTML = `
    <h2 class="pg-h2">Windows Event ID Reference</h2>
    <p class="muted">Searchable reference of ${WIN_EVENTS.length} forensically significant Windows event IDs.
    Type an event ID number or keyword to filter in real-time.</p>
    <div class="tk-row" style="gap:8px;display:flex;align-items:center;flex-wrap:wrap;margin-bottom:8px">
      <input class="tk-f" id="winevt-search" type="text" placeholder="Search by Event ID or description..."
        style="flex:1;min-width:200px">
      <select class="tk-f" id="winevt-channel" style="min-width:140px">
        <option value="all">All Channels</option>
        <option value="Security">Security</option>
        <option value="System">System</option>
        <option value="Application">Application</option>
        <option value="PowerShell">PowerShell</option>
        <option value="Sysmon">Sysmon</option>
        <option value="TaskScheduler">Task Scheduler</option>
        <option value="Defender">Defender</option>
        <option value="Firewall">Firewall</option>
      </select>
      <select class="tk-f" id="winevt-severity" style="min-width:120px">
        <option value="all">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="info">Info</option>
        <option value="low">Low</option>
      </select>
    </div>
    <div style="margin-bottom:6px" id="winevt-count" class="muted"></div>
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333);width:70px">ID</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333);width:100px">Channel</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333);width:80px">Severity</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Description</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Forensic Significance</th>
        </tr></thead>
        <tbody id="winevt-tbody"></tbody>
      </table>
    </div>`;

  const searchInput = root.querySelector("#winevt-search");
  const channelSel = root.querySelector("#winevt-channel");
  const severitySel = root.querySelector("#winevt-severity");
  const tbody = root.querySelector("#winevt-tbody");
  const countEl = root.querySelector("#winevt-count");

  function renderTable() {
    const q = searchInput.value.trim().toLowerCase();
    const ch = channelSel.value;
    const sev = severitySel.value;

    const filtered = WIN_EVENTS.filter((evt) => {
      if (ch !== "all" && evt.channel !== ch) return false;
      if (sev !== "all" && evt.severity !== sev) return false;
      if (q) {
        const idStr = String(evt.id);
        const haystack = (idStr + " " + evt.desc + " " + evt.significance + " " + evt.channel).toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });

    countEl.textContent = `Showing ${filtered.length} of ${WIN_EVENTS.length} events`;

    tbody.innerHTML = filtered.map((evt) => {
      const color = severityColors[evt.severity] || "#888";
      return `<tr>
        <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-family:monospace;font-weight:bold">${evt.id}</td>
        <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-size:0.85em">${escapeHtml(evt.channel)}</td>
        <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">
          <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:600;
            background:${color}22;color:${color};border:1px solid ${color}44">${evt.severity.toUpperCase()}</span>
        </td>
        <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222)">${escapeHtml(evt.desc)}</td>
        <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-size:0.85em" class="muted">${escapeHtml(evt.significance)}</td>
      </tr>`;
    }).join("");
  }

  searchInput.addEventListener("input", renderTable);
  channelSel.addEventListener("change", renderTable);
  severitySel.addEventListener("change", renderTable);

  // Initial render
  renderTable();
}

// ---- Tab 5: Browser Artifacts ----

function renderBrowserArtifacts(root) {
  root.innerHTML = `
    <h2 class="pg-h2">Browser Forensic Artifacts</h2>
    <p class="muted">File paths for browser artifacts on Windows, macOS, and Linux.
    Useful for forensic acquisition and analysis of browsing history, credentials, and session data.</p>
    <div id="browser-cards"></div>`;

  const container = root.querySelector("#browser-cards");

  container.innerHTML = BROWSER_ARTIFACTS.map((browser) => `
    <div class="card" style="padding:16px;margin-bottom:18px">
      <h2 class="pg-h2" style="margin-top:0">${escapeHtml(browser.name)}</h2>
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:0.85em">
          <thead><tr>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333);white-space:nowrap;min-width:120px">Artifact</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Windows</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">macOS</th>
            <th style="text-align:left;padding:6px 10px;border-bottom:2px solid var(--border,#333)">Linux</th>
          </tr></thead>
          <tbody>${browser.paths.map((p) => `<tr>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-weight:600;white-space:nowrap">${escapeHtml(p.artifact)}</td>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-family:monospace;font-size:0.9em;word-break:break-all">${escapeHtml(p.win)}</td>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-family:monospace;font-size:0.9em;word-break:break-all">${escapeHtml(p.mac)}</td>
            <td style="padding:5px 10px;border-bottom:1px solid var(--border,#222);font-family:monospace;font-size:0.9em;word-break:break-all">${escapeHtml(p.linux)}</td>
          </tr>`).join("")}</tbody>
        </table>
      </div>
    </div>
  `).join("");
}

// ---------------------------------------------------------------------------
// SECTION 5: TAB DEFINITIONS + MAIN EXPORT
// ---------------------------------------------------------------------------

const TABS = [
  { id: "file-sigs", label: "File Signatures", render: renderFileSigs },
  { id: "hex-viewer", label: "Hex Viewer", render: renderHexViewer },
  { id: "timestamps", label: "Timestamp Converter", render: renderTimestamps },
  { id: "win-events", label: "Windows Event IDs", render: renderWinEvents },
  { id: "browser-artifacts", label: "Browser Artifacts", render: renderBrowserArtifacts },
];

export function renderForensicsTools(main) {
  main.innerHTML = `
    <div class="dash-hero">
      <div class="eyebrow">Darknode / Forensics</div>
      <h1 class="pg-h1">Digital Forensics Tools</h1>
      <p class="pg-sub">File signature identification, hex analysis, timestamp conversion, Windows event
      reference, and browser artifact paths -- all running locally in your browser. ${FILE_SIGS.length} file
      signatures, ${WIN_EVENTS.length} Windows event IDs, and artifact paths for 4 major browsers.</p>
    </div>
    <div class="tab-bar" id="ftabs"></div>
    <div id="fpanel" class="card" style="padding:20px;margin-top:14px"></div>`;

  const tabBar = main.querySelector("#ftabs");
  const panel = main.querySelector("#fpanel");

  tabBar.innerHTML = TABS.map((t, i) => `<button class="tab${i === 0 ? " active" : ""}" data-id="${t.id}">${t.label}</button>`).join("");

  const activate = (id) => {
    const tab = TABS.find((t) => t.id === id) || TABS[0];
    tabBar.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.id === tab.id));
    panel.innerHTML = "";
    tab.render(panel);
    if (history.replaceState) {
      const url = new URL(location.href);
      url.hash = `forensics-tools/${tab.id}`;
      history.replaceState(null, "", url);
    }
  };

  tabBar.onclick = (e) => {
    const btn = e.target.closest("button[data-id]"); if (!btn) return;
    activate(btn.dataset.id);
  };

  // Deep-link support: #forensics-tools/<tab-id>
  const hashTab = (location.hash || "").split("/")[1];
  activate(hashTab && TABS.some((t) => t.id === hashTab) ? hashTab : TABS[0].id);
}
