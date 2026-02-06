import React, { useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { UploadCloud, FileCode, Loader2 } from 'lucide-react';

const FileUpload = ({ onUpload, isUploading }) => {
    const onDrop = useCallback((acceptedFiles) => {
        if (acceptedFiles.length > 0) {
            onUpload(acceptedFiles[0]);
        }
    }, [onUpload]);

    const { getRootProps, getInputProps, isDragActive } = useDropzone({
        onDrop,
        accept: { 'application/zip': ['.zip'] },
        multiple: false
    });

    return (
        <div
            {...getRootProps()}
            className={`
        border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all duration-300
        flex flex-col items-center justify-center h-64
        ${isDragActive
                    ? 'border-sentry-accent bg-sentry-accent/10'
                    : 'border-gray-700 hover:border-sentry-accent hover:bg-gray-800/50'}
      `}
        >
            <input {...getInputProps()} />

            {isUploading ? (
                <div className="animate-pulse flex flex-col items-center">
                    <Loader2 className="w-12 h-12 text-sentry-accent animate-spin mb-4" />
                    <p className="text-gray-400">Uploading & Extracting...</p>
                </div>
            ) : (
                <>
                    <div className="bg-gray-800 p-4 rounded-full mb-4">
                        <UploadCloud className={`w-8 h-8 ${isDragActive ? 'text-sentry-accent' : 'text-gray-400'}`} />
                    </div>
                    {isDragActive ? (
                        <p className="text-sentry-accent font-medium">Drop the code here to scan!</p>
                    ) : (
                        <>
                            <p className="text-white text-lg font-medium mb-2">Drag & drop your code here</p>
                            <p className="text-gray-500 text-sm">Supports .zip files only</p>
                        </>
                    )}
                </>
            )}
        </div>
    );
};

export default FileUpload;