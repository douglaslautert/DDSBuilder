class DataSourceBase:
    def collect_data(self, search_params):
        """
        Collect vulnerability data based on search parameters.
        This method should be implemented by all data sources.
        """
        raise NotImplementedError("collect_data method must be implemented by the data source.")